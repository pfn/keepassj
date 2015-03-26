using System;
using System.IO;
using System.Linq;
using KeePassLib;
using KeePassLib.Serialization;
using KeePassLib.Keys;
public class test {
    public static void Main(string[] args) {
        CompositeKey key = new CompositeKey();
        KcpPassword pw = new KcpPassword("12345");
        key.AddUserKey(pw);
        byte[] pwdata = pw.KeyData.ReadData();
        Console.WriteLine("PW data:");
        Console.WriteLine(string.Join(",", pwdata.Select(x => "0x" + x.ToString("x"))));
        byte[] keydata = key.GenerateKey32(pwdata, 6000).ReadData();
        Console.WriteLine("Key data:");
        Console.WriteLine(string.Join(",", keydata.Select(x => "0x" + x.ToString("x"))));

        PwDatabase db = new PwDatabase();
        db.MasterKey = key;
        KdbxFile kdbx = new KdbxFile(db);
        kdbx.Load(@"..\resources\test.kdbx", KdbxFormat.Default, null);

        var groups = db.RootGroup.GetGroups(true);
        Console.WriteLine("Group count: " + groups.UCount);
        var entries = db.RootGroup.GetEntries(true);
        Console.WriteLine("Entry count: " + entries.UCount);

        CompositeKey key2 = new CompositeKey();
        key2.AddUserKey(pw);
        KcpKeyFile keyfile = new KcpKeyFile(@"..\resources\keyfile.key");
        key2.AddUserKey(keyfile);
        byte[] keyfiledata = keyfile.KeyData.ReadData();
        Console.WriteLine("Key file data:");
        Console.WriteLine(string.Join(",", keyfiledata.Select(x => "0x" + x.ToString("x"))));
        Console.WriteLine("Composite Key data:");
        byte[] key2data = key2.GenerateKey32(keyfiledata, 6000).ReadData();
        Console.WriteLine(string.Join(",", key2data.Select(x => "0x" + x.ToString("x"))));

    }
}
