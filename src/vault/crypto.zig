const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;
const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const key_len = 32;
pub const salt_len = 32;
pub const nonce_len = XChaCha20Poly1305.nonce_length;
pub const tag_len = XChaCha20Poly1305.tag_length;
pub const magic = "ZCVAULT\x01";
pub const header_len = magic.len + salt_len + nonce_len;

pub const EncryptedBlob = struct {
    salt: [salt_len]u8,
    nonce: [nonce_len]u8,
    ciphertext: []u8, // includes auth tag appended
    tag: [tag_len]u8,
};

pub fn deriveKey(a: std.mem.Allocator, io: std.Io, passphrase: []const u8, salt: [salt_len]u8) ![key_len]u8 {
    var derived: [key_len]u8 = undefined;
    argon2.kdf(
        a,
        &derived,
        passphrase,
        &salt,
        .{ .t = 3, .m = 65536, .p = 1 },
        .argon2id,
        io,
    ) catch return error.KeyDerivationFailed;
    return derived;
}

pub fn encrypt(a: std.mem.Allocator, io: std.Io, key: [key_len]u8, salt: [salt_len]u8, plaintext: []const u8) ![]u8 {
    var nonce: [nonce_len]u8 = undefined;
    io.random(&nonce);

    // Encrypt
    const ct = try a.alloc(u8, plaintext.len);
    defer a.free(ct);
    var tag: [tag_len]u8 = undefined;
    XChaCha20Poly1305.encrypt(ct, &tag, plaintext, "", nonce, key);

    // Build file: magic + salt + nonce + ciphertext + tag
    const total = magic.len + salt_len + nonce_len + ct.len + tag_len;
    const out = try a.alloc(u8, total);
    var pos: usize = 0;

    @memcpy(out[pos..][0..magic.len], magic);
    pos += magic.len;

    @memcpy(out[pos..][0..salt_len], &salt);
    pos += salt_len;

    @memcpy(out[pos..][0..nonce_len], &nonce);
    pos += nonce_len;

    @memcpy(out[pos..][0..ct.len], ct);
    pos += ct.len;

    @memcpy(out[pos..][0..tag_len], &tag);

    return out;
}

pub fn decrypt(a: std.mem.Allocator, key: [key_len]u8, blob: []const u8) ![]u8 {
    if (blob.len < header_len + tag_len) return error.InvalidVaultFile;

    // Verify magic
    if (!std.mem.eql(u8, blob[0..magic.len], magic)) return error.InvalidVaultFile;

    var pos: usize = magic.len;

    // Salt is in the file but we already have the derived key
    pos += salt_len;

    // Extract nonce
    var nonce: [nonce_len]u8 = undefined;
    @memcpy(&nonce, blob[pos..][0..nonce_len]);
    pos += nonce_len;

    // Extract ciphertext and tag
    const ct_len = blob.len - pos - tag_len;
    const ct = blob[pos..][0..ct_len];
    pos += ct_len;

    var tag: [tag_len]u8 = undefined;
    @memcpy(&tag, blob[pos..][0..tag_len]);

    // Decrypt
    const plaintext = try a.alloc(u8, ct_len);
    errdefer a.free(plaintext);

    XChaCha20Poly1305.decrypt(plaintext, ct, tag, "", nonce, key) catch {
        a.free(plaintext);
        return error.DecryptionFailed;
    };

    return plaintext;
}

pub fn extractSalt(blob: []const u8) ![salt_len]u8 {
    if (blob.len < header_len + tag_len) return error.InvalidVaultFile;
    if (!std.mem.eql(u8, blob[0..magic.len], magic)) return error.InvalidVaultFile;
    var salt: [salt_len]u8 = undefined;
    @memcpy(&salt, blob[magic.len..][0..salt_len]);
    return salt;
}

pub fn zeroize(buf: []u8) void {
    @memset(buf, 0);
}
