import io.github.red050911.lib.simpleutils.security.Hash;

public class Test {

    public static void main(String[] args) {
        Hash hash = new Hash(Hash.Type.SHA384, "hahaha");
        System.out.println(hash.getCombinedHashSaltBase64());
    }

}
