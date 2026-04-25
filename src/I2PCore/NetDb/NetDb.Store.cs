using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using I2PCore.Data;
using I2PCore.Utils;
using static System.Configuration.ConfigurationManager;

namespace I2PCore;

public partial class NetDb
{
    private const int DefaultStoreChunkSize = 512;

    public string NetDbPath => Path.GetFullPath(Path.Combine(StreamUtils.AppPath, "NetDb"));

    public string GetFullPath(string filename)
    {
        return Path.Combine(NetDbPath, filename);
    }

    public string GetFullPath(I2PRouterInfo ri)
    {
        var hash = ri.Identity.IdentHash.Id64;
        return GetFullPath(Path.Combine($"r{hash[0]}", $"routerInfo-{hash}.dat"));
    }

    private List<string> GetNetDbFiles()
    {
        var result = new List<string>();

        foreach (var item in Directory.GetDirectories(NetDbPath))
        foreach (var file in Directory.GetFileSystemEntries(item, "routerInfo-*.dat"))
            result.Add(file);

        return result;
    }

    private Store GetStore()
    {
        return BufUtils.GetStore(
            GetFullPath("routerinfo.sto"),
            DefaultStoreChunkSize);
    }

    private void Load()
    {
        using (var s = GetStore())
        {
            var sw2 = new Stopwatch();
            sw2.Start();
            var ix = 0;
            while (s != null && (ix = s.Next(ix)) > 0)
            {
                var reader = new I2PBufferCursor(s.Read(ix));
                var recordtype = (StoreRecordId)reader.ReadUInt32LittleEndian();

                try
                {
                    switch (recordtype)
                    {
                        case StoreRecordId.StoreIdRouterInfo:
                            var one = new I2PRouterInfo(reader, false);

                            if (!ValidateRi(one))
                            {
                                s.Delete(ix);
                                RouterInfos.TryRemove(one.Identity.IdentHash, out _);
                                FloodfillInfos.TryRemove(one.Identity.IdentHash, out _);
                                Statistics.DestinationInformationFaulty(one.Identity.IdentHash);

                                continue;
                            }

                            var re = new RouterEntry(
                                one,
                                new RouterInfoMeta(ix));
                            RouterInfos[one.Identity.IdentHash] = re;
                            if (re.IsFloodfill) FloodfillInfos[one.Identity.IdentHash] = re;
                            break;

                        case StoreRecordId.StoreIdConfig:
                            AccessConfig(delegate(Dictionary<I2PString, I2PString> settings)
                            {
                                var key = new I2PString(reader);
                                settings[key] = new I2PString(reader);
                            });
                            break;

                        default:
                            s.Delete(ix);
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Logging.LogDebug($"NetDb: Load: Store exception, ix [{ix}] removed. {ex}");
                    s.Delete(ix);
                }
            }

            sw2.Stop();
            Logging.Log($"Store: {sw2.Elapsed}");
        }

        ImportNetDbFiles();

        if (RouterInfos.Count < 20 || FloodfillInfos.IsEmpty)
        {
            var reason = RouterInfos.Count < 20
                ? $"too few routers ({RouterInfos.Count})"
                : "no floodfill routers available";
            Logging.LogWarning($"WARNING: NetDB bootstrap needed: {reason}. " +
                               $"Attempting reseed...");

            DoBootstrap();
        }

        Statistics.Load();

        UpdateSelectionProbabilities();
        ShowDebugDatabaseInfo();

        Save(true);
    }

    private void Save(bool onlyupdated)
    {
        var created = 0;
        var updated = 0;
        var deleted = 0;

        var sw = new Stopwatch();
        sw.Start();

        RemoveOldRouterInfos();

        using (var s = GetStore())
        {
            foreach (var one in RouterInfos.ToArray())
                try
                {
                    if (one.Value.Meta.Deleted)
                    {
                        if (one.Value.Meta.StoreIx > 0) s.Delete(one.Value.Meta.StoreIx);
                        RouterInfos.TryRemove(one.Key, out _);
                        FloodfillInfos.TryRemove(one.Key, out _);
                        ++deleted;
                        continue;
                    }

                    if (!onlyupdated || (onlyupdated && one.Value.Meta.Updated))
                    {
                        var rec = new[]
                        {
                            BufUtils.To32Bl((int)StoreRecordId.StoreIdRouterInfo),
                            new(one.Value.Router.ToByteArray())
                        };

                        if (one.Value.Meta.StoreIx > 0)
                        {
                            s.Write(rec, one.Value.Meta.StoreIx);
                            ++updated;
                        }
                        else
                        {
                            one.Value.Meta.StoreIx = s.Write(rec);
                            ++created;
                        }

                        one.Value.Meta.Updated = false;
                    }
                }
                catch (Exception ex)
                {
                    Logging.LogDebug("NetDb: Save: Store exception: " + ex);
                    one.Value.Meta.StoreIx = -1;
                }

            SaveConfig(s);
        }

        Logging.Log($"NetDb.Save( {(onlyupdated ? "updated" : "all")} ): " +
                    $"{created} created, {updated} updated, {deleted} deleted.");

        UpdateSelectionProbabilities();

        sw.Stop();
        Logging.Log($"NetDB: Save: {sw.Elapsed}");
    }

    private void SaveConfig(Store s)
    {
        var lookup = s.GetMatching(e => (StoreRecordId)e[0] == StoreRecordId.StoreIdConfig, 1);
        var str2Ix = new Dictionary<I2PString, int>();
        foreach (var one in lookup)
        {
            var reader = new I2PBufferCursor(one.Value);
            reader.ReadUInt32LittleEndian();
            var key = new I2PString(reader);
            str2Ix[key] = one.Key;
        }

        AccessConfig(delegate(Dictionary<I2PString, I2PString> settings)
        {
            foreach (var one in settings)
            {
                var rec = new[]
                {
                    BufUtils.To32Bl((int)StoreRecordId.StoreIdConfig),
                    new(one.Key.ToByteArray()), new(one.Value.ToByteArray())
                };

                if (str2Ix.ContainsKey(one.Key))
                    s.Write(rec, str2Ix[one.Key]);
                else
                    s.Write(rec);
            }
        });
    }

    private void RemoveOldRouterInfos()
    {
        var inactive = Statistics.GetInactive();
        RemoveRouterInfo(inactive);
        Statistics.RemoveOldStatistics(RouterInfos.Keys);
    }

    private void ImportNetDbFiles()
    {
        var importfiles = GetNetDbFiles();
        foreach (var file in importfiles) AddRouterInfo(file);

        foreach (var file in importfiles) File.Delete(file);
    }

    private void DoBootstrap()
    {
        var imported = 0;

        if (!string.IsNullOrWhiteSpace(AppSettings["ReseedFile"]))
        {
            var filename = AppSettings["ReseedFile"];
            imported += Bootstrap.FileBootstrap(filename);
        }

        if (imported == 0)
        {
            var t = Bootstrap.NetworkBootstrap();
            t.ConfigureAwait(false);
            imported += t.Result;
        }
    }

    private enum StoreRecordId
    {
        StoreIdRouterInfo = 1,
        StoreIdLeaseSet = 2,
        StoreIdConfig = 3
    }

    protected class RouterInfoMeta
    {
        public bool Deleted;
        public I2PIdentHash Id;
        public int StoreIx;
        public bool Updated;

        public RouterInfoMeta(I2PIdentHash id)
        {
            Id = id;
            StoreIx = -1;
        }

        public RouterInfoMeta(int storeix)
        {
            StoreIx = storeix;
        }
    }
}