// Fill out your copyright notice in the Description page of Project Settings.


#include "Picohash.h"


FString Picohash::BytesToHex(const uint8* Bytes, int32 Length)
{
	FString HexString;
	for (int32 i = 0; i < Length; i++)
	{
		HexString += FString::Printf(TEXT("%02x"), Bytes[i]);
	}
	return HexString;
}

FString Picohash::BytesToBase64(const uint8* Bytes, int32 Length)
{
	return FBase64::Encode(Bytes, Length);
}

FString Picohash::MD5(const FString& Input)
{
	if (Input.IsEmpty())
	{
		return FString();
	}

	FTCHARToUTF8 InputConverter(*Input);
	const char * InputStr = InputConverter.Get();
	const int32 InputLen = InputConverter.Length();
	//const char* InputStr = TCHAR_TO_UTF8(*Input);
	picohash_ctx_t ctx;
	picohash_init_md5(&ctx);
	picohash_update(&ctx, InputStr, InputLen);
	uint8 Digest[PICOHASH_MD5_DIGEST_LENGTH];
	picohash_final(&ctx, Digest);
	return BytesToHex(Digest, PICOHASH_MD5_DIGEST_LENGTH);
}

FString Picohash::SHA1(const FString& Input)
{
	if (Input.IsEmpty())
	{
		return FString();
	}
	FTCHARToUTF8 InputConverter(*Input);
	const char* InputStr = InputConverter.Get();
	const int32 InputLen = InputConverter.Length();
	//const char* InputStr = TCHAR_TO_UTF8(*Input);

	picohash_ctx_t ctx;
	picohash_init_sha1(&ctx);
	picohash_update(&ctx, InputStr, InputLen);
	uint8 Digest[PICOHASH_SHA1_DIGEST_LENGTH];
	picohash_final(&ctx, Digest);
	return BytesToHex(Digest, PICOHASH_SHA1_DIGEST_LENGTH);
}

FString Picohash::SHA224(const FString& Input)
{
	if (Input.IsEmpty())
	{
		return FString();
	}
	FTCHARToUTF8 InputConverter(*Input);
	const char* InputStr = InputConverter.Get();
	const int32 InputLen = InputConverter.Length();
	//const char* InputStr = TCHAR_TO_UTF8(*Input);
	picohash_ctx_t ctx;
	picohash_init_sha224(&ctx);
	picohash_update(&ctx, InputStr, InputLen);
	uint8 Digest[PICOHASH_SHA224_DIGEST_LENGTH];
	picohash_final(&ctx, Digest);
	return BytesToHex(Digest, PICOHASH_SHA224_DIGEST_LENGTH);
}

FString Picohash::SHA256(const FString& Input)
{
	if (Input.IsEmpty())
	{
		return FString();
	}
	FTCHARToUTF8 InputConverter(*Input);
	const char* InputStr = InputConverter.Get();
	const int32 InputLen = InputConverter.Length();
	//const char* InputStr = TCHAR_TO_UTF8(*Input);
	picohash_ctx_t ctx;
	picohash_init_sha256(&ctx);
	picohash_update(&ctx, InputStr, InputLen);
	uint8 Digest[PICOHASH_SHA256_DIGEST_LENGTH];
	picohash_final(&ctx, Digest);
	return BytesToHex(Digest, PICOHASH_SHA256_DIGEST_LENGTH);
}

FString Picohash::HMAC_MD5(const FString& Message, const FString& Key)
{
	if (Message.IsEmpty() || Key.IsEmpty())
	{
		return FString();
	}
	//const char* KeyStr = TCHAR_TO_UTF8(*Key);
	//const char* MessageStr = TCHAR_TO_UTF8(*Message);
	FTCHARToUTF8 MessageConverter(*Message);
	FTCHARToUTF8 KeyConverter(*Key);

	const char* MessageStr = MessageConverter.Get();
	const char* KeyStr = KeyConverter.Get();

	const int32 MessageLen = MessageConverter.Length();
	const int32 KeyLen = KeyConverter.Length();
	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_md5, KeyStr, KeyLen);
	picohash_update(&ctx, MessageStr, MessageLen);
	uint8 Digest[PICOHASH_MD5_DIGEST_LENGTH];
	picohash_final(&ctx, Digest);
	return BytesToHex(Digest, PICOHASH_MD5_DIGEST_LENGTH);
}

FString Picohash::HMAC_SHA1(const FString& Message, const FString& Key)
{
	if (Message.IsEmpty() || Key.IsEmpty())
	{
		return FString();
	}
	/*const char* KeyStr = TCHAR_TO_UTF8(*Key);
	const char* MessageStr = TCHAR_TO_UTF8(*Message);*/
	FTCHARToUTF8 MessageConverter(*Message);
	FTCHARToUTF8 KeyConverter(*Key);

	const char* MessageStr = MessageConverter.Get();
	const char* KeyStr = KeyConverter.Get();

	const int32 MessageLen = MessageConverter.Length();
	const int32 KeyLen = KeyConverter.Length();

	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_sha1, KeyStr, KeyLen);
	picohash_update(&ctx, MessageStr, MessageLen);
	uint8 Digest[PICOHASH_SHA1_DIGEST_LENGTH];
	picohash_final(&ctx, Digest);
	return BytesToHex(Digest, PICOHASH_SHA1_DIGEST_LENGTH);
}

FString Picohash::HMAC_SHA224(const FString& Message, const FString& Key)
{
	if (Message.IsEmpty() || Key.IsEmpty())
	{
		return FString();
	}

	/*const char* KeyStr = TCHAR_TO_UTF8(*Key);
	const char* MessageStr = TCHAR_TO_UTF8(*Message);*/
	FTCHARToUTF8 MessageConverter(*Message);
	FTCHARToUTF8 KeyConverter(*Key);

	const char* MessageStr = MessageConverter.Get();
	const char* KeyStr = KeyConverter.Get();

	const int32 MessageLen = MessageConverter.Length();
	const int32 KeyLen = KeyConverter.Length();
	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_sha224, KeyStr, KeyLen);
	picohash_update(&ctx, MessageStr, MessageLen);
	uint8 Digest[PICOHASH_SHA224_DIGEST_LENGTH];
	picohash_final(&ctx, Digest);
	return BytesToHex(Digest, PICOHASH_SHA224_DIGEST_LENGTH);
}

FString Picohash::HMAC_SHA256(const FString& Message, const FString& Key)
{
	if (Message.IsEmpty() || Key.IsEmpty())
	{
		return FString();
	}
	/*const char* KeyStr = TCHAR_TO_UTF8(*Key);
	const char* MessageStr = TCHAR_TO_UTF8(*Message);*/
	FTCHARToUTF8 MessageConverter(*Message);
	FTCHARToUTF8 KeyConverter(*Key);

	const char* MessageStr = MessageConverter.Get();
	const char* KeyStr = KeyConverter.Get();

	const int32 MessageLen = MessageConverter.Length();
	const int32 KeyLen = KeyConverter.Length();
	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_sha256, KeyStr, KeyLen);
	picohash_update(&ctx, MessageStr, MessageLen);
	uint8 Digest[PICOHASH_SHA256_DIGEST_LENGTH];
	picohash_final(&ctx, Digest);
	return BytesToHex(Digest, PICOHASH_SHA256_DIGEST_LENGTH);
}

FString Picohash::HMAC_MD5Base64(const FString& Message, const FString& Key)
{
	if (Message.IsEmpty() || Key.IsEmpty())
	{
		return FString();
	}
	/*const char* KeyStr = TCHAR_TO_UTF8(*Key);
	const char* MessageStr = TCHAR_TO_UTF8(*Message);*/
	FTCHARToUTF8 MessageConverter(*Message);
	FTCHARToUTF8 KeyConverter(*Key);

	const char* MessageStr = MessageConverter.Get();
	const char* KeyStr = KeyConverter.Get();

	const int32 MessageLen = MessageConverter.Length();
	const int32 KeyLen = KeyConverter.Length();
	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_md5, KeyStr, KeyLen);
	picohash_update(&ctx, MessageStr, MessageLen);
	uint8 Digest[PICOHASH_MD5_DIGEST_LENGTH];
	picohash_final(&ctx, Digest);
	return BytesToBase64(Digest, PICOHASH_MD5_DIGEST_LENGTH);
}

FString Picohash::HMAC_SHA1Base64(const FString& Message, const FString& Key)
{
	/*const char* KeyStr = TCHAR_TO_UTF8(*Key);
	const char* MessageStr = TCHAR_TO_UTF8(*Message);*/
	if (Message.IsEmpty() || Key.IsEmpty())
	{
		return FString();
	}
	FTCHARToUTF8 MessageConverter(*Message);
	FTCHARToUTF8 KeyConverter(*Key);

	const char* MessageStr = MessageConverter.Get();
	const char* KeyStr = KeyConverter.Get();

	const int32 MessageLen = MessageConverter.Length();
	const int32 KeyLen = KeyConverter.Length();
	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_sha1, KeyStr, KeyLen);
	picohash_update(&ctx, MessageStr, MessageLen);
	uint8 Digest[PICOHASH_SHA1_DIGEST_LENGTH];
	picohash_final(&ctx, Digest);
	return BytesToBase64(Digest, PICOHASH_SHA1_DIGEST_LENGTH);
}

FString Picohash::HMAC_SHA224Base64(const FString& Message, const FString& Key)
{
	/*const char* KeyStr = TCHAR_TO_UTF8(*Key);
	const char* MessageStr = TCHAR_TO_UTF8(*Message);*/
	if (Message.IsEmpty() || Key.IsEmpty())
	{
		return FString();
	}
	FTCHARToUTF8 MessageConverter(*Message);
	FTCHARToUTF8 KeyConverter(*Key);

	const char* MessageStr = MessageConverter.Get();
	const char* KeyStr = KeyConverter.Get();

	const int32 MessageLen = MessageConverter.Length();
	const int32 KeyLen = KeyConverter.Length();
	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_sha224, KeyStr, KeyLen);
	picohash_update(&ctx, MessageStr, MessageLen);
	uint8 Digest[PICOHASH_SHA224_DIGEST_LENGTH];
	picohash_final(&ctx, Digest);
	return BytesToBase64(Digest, PICOHASH_SHA224_DIGEST_LENGTH);
}

FString Picohash::HMAC_SHA256Base64(const FString& Message, const FString& Key)
{
	/*const char* KeyStr = TCHAR_TO_UTF8(*Key);
	const char* MessageStr = TCHAR_TO_UTF8(*Message);*/
	if (Message.IsEmpty() || Key.IsEmpty())
	{
		return FString();
	}
	FTCHARToUTF8 MessageConverter(*Message);
	FTCHARToUTF8 KeyConverter(*Key);

	const char* MessageStr = MessageConverter.Get();
	const char* KeyStr = KeyConverter.Get();

	const int32 MessageLen = MessageConverter.Length();
	const int32 KeyLen = KeyConverter.Length();

	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_sha256, KeyStr, KeyLen);
	picohash_update(&ctx, MessageStr, MessageLen);
	uint8 Digest[PICOHASH_SHA256_DIGEST_LENGTH];
	picohash_final(&ctx, Digest);
	return BytesToBase64(Digest, PICOHASH_SHA256_DIGEST_LENGTH);
}