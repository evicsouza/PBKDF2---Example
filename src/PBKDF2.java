import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2 {

	static Scanner sc = new Scanner(System.in);

	public static void main(String[] args) 
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		System.out.println("DIGITE A SENHA ORIGINAL:");
		String senhaOriginal = sc.next();
		String gerarSenhaHashSegura = gerarHashSenhaForte(senhaOriginal);
		System.out.println("SENHA CRIPTOGRAFADA: " + "\n" + gerarSenhaHashSegura);

	}

	private static String gerarHashSenhaForte(String senha) 
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		int interacoes = 1000;
		char[] chars = senha.toCharArray();
		byte[] salto = getSalt();

		PBEKeySpec spec = new PBEKeySpec(chars, salto, interacoes, 64 * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		byte[] hash = skf.generateSecret(spec).getEncoded();
		return interacoes + ":" + toHex(salto) + ":" + toHex(hash);
	}
	private static byte[] getSalt() throws NoSuchAlgorithmException
	{
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		byte[] salt = new byte[16];
		sr.nextBytes(salt);
		return salt;
	}

	private static String toHex(byte[] array) throws NoSuchAlgorithmException
	{
		BigInteger bi = new BigInteger(1, array);
		String hex = bi.toString(16);
		int paddingLength = (array.length * 2) - hex.length();
		if(paddingLength > 0)
		{
			return String.format("%0"  +paddingLength + "d", 0) + hex;
		}else{
			return hex;
		}

	}
}