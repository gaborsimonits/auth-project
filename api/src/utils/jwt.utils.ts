import jwt from "jsonwebtoken";

const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCxDGWRgCKajTAPV/sL4aN4/KzX8+HSkUbzoiuDBufcR7qCqc2O
eRpM9QlsEvRUspFredxwchuspuBCWiKy5Bs2Gy3t3waj2MUtbG/8HF43aLfMVr61
rHFt9V+vzGbOoIWKh+qKxU1Qj2eI7I7IGocUp+KgdmjKTpU/BsAKMGj9pQIDAQAB
AoGAJyv6/OpAvbknPP3WSZauuIIPK+iFujTyYc0rm13XxuEH3wj6td8NdqFwaDz5
WhP4ILNhlm9ouBZj38pZiwL1EfB8gZW+RooWt+ZA2inMWrF3bxHTYfvwnDADECue
xwXcp/lhNZO/YPM6ZbPBTGQtbmiyFJL/NfnUwCDMHGRzDQECQQDzW2hJ0e6eMNj/
Q2e+1UKDq1WK8nGzptFGcDkbnlCr9YxTlYDU7kYbs0wysyT2/mV/Ww+as8dXdtQp
E+71UBlVAkEAuj8ZkGf5OukKHciAr59Vrvx+isiYuodg/3TK0rMeLrBgHo9j0ntY
76emelElwtJv6k3YqRNqDZlDSn6bC14TEQJAIh8N51PVFj8ZHelwkXRLaDTMwLev
s5XPQAYaK8It436BV3Ld5n0mPVoNdApkQ3F1/75f2LweVigmJUBTP/gkJQJAVJ28
cJY8bl5YIUXp6WB7nj/LAiS29u/wyr72Mxn72Xx6fwfoc0VlF6TUhvf9LvFKtWne
yJowcbMzFlJFALoh8QJAY1DDOzf7KwniKv6/F3Dcdwl93Jowy89BD3pNYYzu6W83
X9Da81/bh4HUH4gXOgCqV2jM4WQbY5xlWt2dh58OjA==
-----END RSA PRIVATE KEY-----`;

const publicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxDGWRgCKajTAPV/sL4aN4/KzX
8+HSkUbzoiuDBufcR7qCqc2OeRpM9QlsEvRUspFredxwchuspuBCWiKy5Bs2Gy3t
3waj2MUtbG/8HF43aLfMVr61rHFt9V+vzGbOoIWKh+qKxU1Qj2eI7I7IGocUp+Kg
dmjKTpU/BsAKMGj9pQIDAQAB
-----END PUBLIC KEY-----`;

// sign jwt
export function signJWT(payload: object, expiresIn: string | number) {
	return jwt.sign(payload, privateKey, { algorithm: "RS256", expiresIn });
}

// verify jwt
export function verifyJWT(token: string) {
	try {
		const decoded = jwt.verify(token, publicKey);
		return { payload: decoded, expired: false };
	} catch (e: any) {
		return { payload: null, expired: e.message.includes("jwt expired") };
	}
}
