namespace I2PCore.Utils;

public class RefPair<TL, TR>
{
    public RefPair(TL l, TR r)
    {
        Left = l;
        Right = r;
    }

    public TL Left { get; set; }
    public TR Right { get; set; }
}