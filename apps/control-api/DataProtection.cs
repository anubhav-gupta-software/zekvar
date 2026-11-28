using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Control;

// Application-level encryption for confidential tenant configuration stored in PostgreSQL.
// Envelope: "zk2:<key id>:<base64url(nonce | ciphertext | tag)>", AES-256-GCM, with the organization, field, and row identity bound as
// associated data, so a sealed value copied to another row or tenant does not open. Values sealed before row binding use "zk1" and are
// readable only by the startup re-seal, which rewrites them as "zk2".
// Control:DataKeys is "id=hex,id=hex"; the first key seals new values and every listed key can open existing values.
internal sealed class DataProtection
{
    public const string Prefix = "zk2";
    public const string LegacyPrefix = "zk1";
    private readonly Dictionary<string, byte[]> keys = new(StringComparer.Ordinal);

    public string? ActiveKeyId { get; }
    public bool Enabled => ActiveKeyId is not null;
    public IReadOnlyCollection<string> KeyIds => keys.Keys;

    private DataProtection(string? active) => ActiveKeyId = active;

    public static readonly DataProtection Disabled = new(null);

    public static DataProtection Read(IConfiguration configuration, bool hosted, IEnumerable<string> otherSecrets)
    {
        var value = configuration["Control:DataKeys"];
        if (string.IsNullOrWhiteSpace(value))
        {
            if (hosted) throw new InvalidOperationException("Configure Control__DataKeys with at least one id=64-hex-character data key for the hosted pilot.");
            return Disabled;
        }
        DataProtection? ring = null;
        var reserved = otherSecrets.Where(secret => !string.IsNullOrEmpty(secret)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = entry.Split('=', 2);
            if (parts.Length != 2 || !ValidKeyId(parts[0]) || !Tokens.IsValid(parts[1]) || reserved.Contains(parts[1]))
                throw new InvalidOperationException("Configure Control__DataKeys as comma-separated id=64-hex-character keys, distinct from other Control secrets.");
            ring ??= new DataProtection(parts[0]);
            var key = Convert.FromHexString(parts[1]);
            if (!ring.keys.TryAdd(parts[0], key) || ring.keys.Values.Count(other => other.AsSpan().SequenceEqual(key)) > 1)
                throw new InvalidOperationException("Use a distinct id and key for each Control data key.");
        }
        return ring ?? throw new InvalidOperationException("Configure at least one Control data key.");
    }

    public static bool ValidKeyId(string? id) => id is { Length: >= 1 and <= 32 } &&
        id.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.');

    public static string? KeyIdOf(string envelope)
    {
        var parts = envelope.Split(':');
        return parts.Length == 3 && (parts[0] == Prefix || parts[0] == LegacyPrefix) ? parts[1] : null;
    }

    public string Seal(string plaintext, Guid organizationId, string field, string rowId)
    {
        if (ActiveKeyId is not { } id) throw new InvalidOperationException("Control data encryption is not configured.");
        var nonce = RandomNumberGenerator.GetBytes(12);
        var input = Encoding.UTF8.GetBytes(plaintext);
        var output = new byte[12 + input.Length + 16];
        nonce.CopyTo(output, 0);
        using var aes = new AesGcm(keys[id], 16);
        aes.Encrypt(nonce, input, output.AsSpan(12, input.Length), output.AsSpan(12 + input.Length), Associated(Prefix, id, organizationId, field, rowId));
        return $"{Prefix}:{id}:{Convert.ToBase64String(output).TrimEnd('=').Replace('+', '-').Replace('/', '_')}";
    }

    // legacy is true only for the startup re-seal, which must read values sealed before row binding in order to rewrite them.
    public string Open(string envelope, Guid organizationId, string field, string rowId, bool legacy = false)
    {
        var parts = envelope.Split(':');
        if (parts.Length != 3 || !(parts[0] == Prefix || legacy && parts[0] == LegacyPrefix) || !keys.TryGetValue(parts[1], out var key))
            throw new InvalidOperationException("A sealed Control value uses an unavailable data key. Restore the key that sealed it to Control__DataKeys.");
        var text = parts[2].Replace('-', '+').Replace('_', '/');
        var data = Convert.FromBase64String(text.PadRight(text.Length + (4 - text.Length % 4) % 4, '='));
        if (data.Length < 28) throw new CryptographicException("Sealed Control value is truncated.");
        var plaintext = new byte[data.Length - 28];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(data.AsSpan(0, 12), data.AsSpan(12, plaintext.Length), data.AsSpan(12 + plaintext.Length), plaintext,
            Associated(parts[0], parts[1], organizationId, field, parts[0] == LegacyPrefix ? null : rowId));
        return Encoding.UTF8.GetString(plaintext);
    }

    private static byte[] Associated(string prefix, string keyId, Guid organizationId, string field, string? rowId) =>
        Encoding.UTF8.GetBytes(rowId is null ? $"zekvar-control/{prefix}/{keyId}/{organizationId:D}/{field}"
            : $"zekvar-control/{prefix}/{keyId}/{organizationId:D}/{field}/{rowId}");

    // Seals one array member of a JSON object, keeping the other members (such as mode) readable by SQL.
    public string SealMember(string json, string member, Guid organizationId, string field, string rowId)
    {
        if (!Enabled) return json;
        var node = JsonNode.Parse(json)!.AsObject();
        if (node["sealed"] is not null) return json;
        if (node[member] is not JsonArray values || values.Count == 0) return json;
        node["sealed"] = Seal(values.ToJsonString(), organizationId, field, rowId);
        node[member] = new JsonArray();
        return node.ToJsonString();
    }

    public string OpenMember(string json, string member, Guid organizationId, string field, string rowId, bool legacy = false)
    {
        if (!json.Contains("\"sealed\"", StringComparison.Ordinal)) return json;
        var node = JsonNode.Parse(json)!.AsObject();
        if (node["sealed"]?.GetValue<string>() is not { } envelope) return json;
        node[member] = JsonNode.Parse(Open(envelope, organizationId, field, rowId, legacy));
        node.Remove("sealed");
        return node.ToJsonString();
    }

    // Seals a whole JSON object except the listed members, which stay readable by SQL lookups.
    public string SealObject(string json, Guid organizationId, string field, string rowId, params string[] keep)
    {
        if (!Enabled) return json;
        var node = JsonNode.Parse(json)!.AsObject();
        if (node["sealed"] is not null) return json;
        var result = new JsonObject();
        foreach (var name in keep)
            if (node[name] is { } value) { node.Remove(name); result[name] = value; }
        result["sealed"] = Seal(node.ToJsonString(), organizationId, field, rowId);
        return result.ToJsonString();
    }

    public string OpenObject(string json, Guid organizationId, string field, string rowId, bool legacy = false)
    {
        if (!json.Contains("\"sealed\"", StringComparison.Ordinal)) return json;
        var node = JsonNode.Parse(json)!.AsObject();
        if (node["sealed"]?.GetValue<string>() is not { } envelope) return json;
        var opened = JsonNode.Parse(Open(envelope, organizationId, field, rowId, legacy))!.AsObject();
        foreach (var (name, value) in node.ToArray())
            if (name != "sealed") { node.Remove(name); opened[name] = value; }
        return opened.ToJsonString();
    }
}
