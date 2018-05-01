package edu.nau.rtisnl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.security.crypto.password.PasswordEncoder;

public class SegaPasswordEncoder implements PasswordEncoder{

	static int DRUPAL_MIN_HASH_COUNT = 7;
	static int DRUPAL_MAX_HASH_COUNT = 55;
	static String itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	@Override
	public String encode(CharSequence rawPassword) {

		/*We don't actually use this password - the encoded password used in the "matches" method 
		comes from the stored password in the DB, so this can be quite literally "anything" (except for null)
		*/
		return "anything";
	}

	/*
	 * Adapted from: https://api.drupal.org/api/drupal/includes%21password.inc/function/_password_crypt/7.x
	 */

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		String input = rawPassword.toString();
		if(input.length() > 512){
			return false;
		}

		String setting = encodedPassword.substring(0,12);
		if(setting.charAt(0) != '$' || setting.charAt(2) != '$'){
			return false;
		}

		int firstOccurance = itoa64.indexOf(setting.charAt(3));
		if(firstOccurance < DRUPAL_MIN_HASH_COUNT || firstOccurance > DRUPAL_MAX_HASH_COUNT){
			return false;
		}

		String salt = setting.substring(4);
		if(salt.length() != 8){
			return false;
		}


		int count = 1 << firstOccurance;
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-512");

			md.update((salt + input).getBytes());
			byte[] result = md.digest();

			byte[] password = input.getBytes();
			byte[] combo;

			for(int i = count; i > 0; i--){
				combo = new byte[result.length + password.length];
				System.arraycopy(result, 0, combo, 0, result.length);
				System.arraycopy(password, 0, combo, result.length, password.length);
				md.reset();		
				md.update(combo);
				result = md.digest();


			}		



			String resultStr = (setting + base64Encode(result)).substring(0,DRUPAL_MAX_HASH_COUNT);	

			return resultStr.equals(encodedPassword);
			
		} catch (NoSuchAlgorithmException e) {
			//TODO how to log this?
			e.printStackTrace();
			return false;
		}
	}


	/**
	 * Adapted from: https://api.drupal.org/api/drupal/includes%21password.inc/function/_password_crypt/7.x
	 * 
	 * 
	 * @param input
	 * @param stored_pass
	 * @return
	 * @throws NoSuchAlgorithmException 
	 */
	public boolean isPassword(String input, String stored_pass) throws NoSuchAlgorithmException{
		if(input.length() > 512){
			return false;
		}

		String setting = stored_pass.substring(0,12);
		if(setting.charAt(0) != '$' || setting.charAt(2) != '$'){
			return false;
		}

		int firstOccurance = itoa64.indexOf(setting.charAt(3));
		if(firstOccurance < DRUPAL_MIN_HASH_COUNT || firstOccurance > DRUPAL_MAX_HASH_COUNT){
			return false;
		}

		String salt = setting.substring(4);
		if(salt.length() != 8){
			return false;
		}


		int count = 1 << firstOccurance;
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		md.update((salt + input).getBytes());
		byte[] result = md.digest();

		byte[] password = input.getBytes();
		byte[] combo;

		for(int i = count; i > 0; i--){
			combo = new byte[result.length + password.length];
			System.arraycopy(result, 0, combo, 0, result.length);
			System.arraycopy(password, 0, combo, result.length, password.length);
			md.reset();		
			md.update(combo);
			result = md.digest();


		}		



		String resultStr = (setting + base64Encode(result)).substring(0,DRUPAL_MAX_HASH_COUNT);	
		//System.out.println(resultStr);
		//System.out.println(stored_pass);
		return resultStr.equals(stored_pass);


	}

	public String base64Encode(byte[] bytes){
		String output = "";
		int i = 0;
		int value;
		int count = bytes.length;
		do{
			value = (bytes[i++] & 0xFF);

			output += itoa64.charAt(value & 0x3F);

			if (i < count) {		    	
				value |= ((bytes[i] & 0xFF) << 8);
			}

			output += itoa64.charAt((value >> 6) & 0x3f);
			if(i++ >= count){
				break;
			}

			if(i < count){
				value |= ((bytes[i] & 0xFF) << 16);
			}

			output += itoa64.charAt((value >> 12) & 0x3f);

			if (i++ >= count) {
				break;
			}

			output += itoa64.charAt((value >> 18) & 0x3f);	


		}while(i < count);


		return output;
	}




}
