// ─────────────────────────────────────────────────────────
// @aria-registry/verify — ARIA Registry Trust Anchor
// Part of the ARIA Protocol by TrustLayer Foundation
// https://aria.bar/docs/sdk
// ─────────────────────────────────────────────────────────
//
// PRODUCTION KEYS — ARIA Registry root public keys.
// These are the keys that sign ALL AIDs at registry.aria.bar.
// The private keys exist ONLY in aria-core and are never exposed.
//
// Use setRegistryKeys() to override for custom registries or testing.

/**
 * Convert a hexadecimal string to a `Uint8Array`.
 * @internal
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * ML-DSA-65 (FIPS 204) public key of the ARIA Registry.
 * Used to verify the post-quantum signature on every AID.
 *
 * @remarks Can be overridden at runtime via {@link setRegistryKeys}
 * for custom registries or key rotation scenarios.
 */
export let REGISTRY_PUBLIC_KEY_MLDSA65: Uint8Array = hexToBytes('d9407672a8d1d563bb5ec5ed8554a69e1e4f8393d2c86e661680aa13d1c59327545323f601ed10fe46040dbf6a24da7fb1dc49f1152e83b49628c68a54076fdd882c272e9dccf3257ecc4ca9699159961520047cfffc8d94ce10a68bb1fc0327b8304c91f0a3345b19e9e31de96b837471e29f3d61d3101d0ef0e79193986740add3795b1c9e98e381214c0b8f568dd889d13429d5ed2e7f6b33bd10cb9d05469a0eedeb5687bd4773cb5f8f0ceb2da23d12567bc645b58aa6444929ccc3175eae9f8b2d727f60ac42bb3066391d3d736465f5f952f7b3872f824af86ee1824b95abfe215408402691c56e31cb3c8cc262d9dfb0826221a6a9cd4ea48fbf236e7ffaeab7d753194e538317ba913ebff1444baf43729d3c31e959035f503dd99de402ef05e2e418a4e413ea74b6bc8bbafcc8613a2828c46af039ca02580f8bd96d2d336a57d6bbbc3307b27ac09e94beb6731ecc0a68be996508280e450cb7cd11d8626e30b15153053bce2a152d5e5f76ac178c4cb41f31aa68580f4bcd2f606d7a21c40451aa786c9d333f3e9935917233e400c7d4a86b0977e01b1c818f237b5feef6f99362b509c78e0071e11acd19e4660c49f064cdebb1c64f632ba2d725eb44a7fcc6cc249fe93e3ad257a18fa87e9f9ed38d6fabdc37eebedbd7f21a2a28ce0a5a101dc4f9302623c0885afaeb59eeb572952141aefa0e0b8cb5e777948a3aaedfd70c52014ecab517b83a560ebee8109a6ddbf74dc7a2ac0894f6c5470716b5d47720cae460a4886aaa4df3dfc68104347e923fb658802cf03c1c02b44a52459e867c1fb4fcc142c09edb998ffff23be26b0d9ca19136b4e9edcb3eafbb6590fb4166de247a903ae20a1bd6ac4eb660543a9b81d735a5a146cf3e136a72f6e8c3e354ef2cd57eb45ee8bb8db5a4a6865dce2596ee31badaee3a5a8e441e628f73530205cba4118b53db6675d4dadb5dfaebe89826a1bfe772df4754c2051ae42a0660efce9beb0713d943a7922ce25fe33c8320cceb2d2963e250a2eedc51779efd88c78e68b222f980828a5b1bec93662e6daa9df8e204e646bc43aa8ebc0c66ba48a9e2f363335418c0285c443193047baf3729f4611c48f6cf49a9f739df3a3447486659397fa075b5c5960c57313ce6360d0b074797b12eaf9e8195498feaa9a0f5ed9af29007bf203b4fa675a7b2bc93695cd75b3fe1ab4f3b09880806f597a3c297b0aee84b6cdd7de80f9203d9e0bfaf3cd1462ff5c5efbc3d9a65db29a71cac003d2ab40d05720f3734432238c78b205dc569a9f18e853323819c4444ff32a444e0fafaf3bd4104b2a779f0daa034565dc87866670a9472b7015579f9c5d6dbc7ca0376fb0d000768edb9b39184281762874091a37c4de1632ca693fa0bf0f48ff5804a838834ea70e2e38b71503f3bcea86357c62e72a7d505fce6a237c9efb47f92e48b6563ae51f7258712e826604dd1d86a1877769805b31cbc9d6a6d47e2597be386d67ef21ea3bccd65405e3be744aca04b9f4743b20438ad968bf95923e3468d900fb11da1b4cb46772c9ac221af1c9363f7af478ddd96b0184afce4e208f1f73a61edae9e8f7b9e9004272778fe183a74aa0924645cb0148cc72a49bd775e450c1f5cca9f4578eaf3feb446952ba8489194bef386be0ecca46fb1221e0271c528d2516603829a0dc5b42d1104375e01cbed04e609251031fa0da6d2520d390aa7336d216cc22ec8e7c42e7de301e4f28558bc47363736c5df732fda1fa3283ed5f2c6602522fc50a1f412bd992842c2e7f864bdc0e97c20eaf583da6ba8691c4c535a15773f6ba943b1ca4a6301fe7d96ca4c23f371ef2472585b2b496e5de7e305d6385135dfc84cc06701ce40d2b4ae7a7251605bb6a9316c0611ad089e4107066ffa61df22f5ebdf466771592a3ac9d9d44eb480265068fe8d7698ce307f1f7d4fb4b36def59573b9e2c00fe00b58584a7c140c0d0c518876d51a904c03a2daa830df39cc12d2441cab19bb481b1aaf7a25e0aa0f50c01815a2cc00a5b35270284abf51aec53c8c889cf8599733755348352688030e0e7240a27bf51e1d3420d76d5a8b39aac813439e90ecc22ab0f7e2a5a334027e069db4c1e013dda2ff21693a1a63970a8d3517989ea70f630771c82c1aacc637da9909cf86be9b356c4157efdcc3fa11183458a325ea233292b43a0d5ecb7b3c5d280ab43060552a4906ddf918196ed7d4a5d4e748a87a1485a29764630607f23b82cd74493e5b8f53a7b17b7457d9cf42c61c47643732172bf51e59ac2799998b178894400918a5847732cff946dc9a15f4b595a07573ebb76d742ca9ef703db97197c98cd31b29929ae118754bc515f582df7017b0c605a5697a9fb019b8386be481617d4cdf9a974144995193bc33727656e509bd2bec272b1b05aa110fa45844c109c96ab34a4eaf973bf06769c2e1ce333dd538ee645c8cbbd5fa031d3afc3bb2d945ca61d9db5381b3e7d81367e010e3c2af4bd19a0b4b6b0e5b1a5068ae642470c6fa75834888c3e007209ed8b62defb2ab569a49833700e0befc6dc55ca9d4e25918d8d257b4616d8611ff6bde79f8514314a87f6cb5c4931b4e8962a4ae1375d5c8bf565bf09e9fe65b3cd933cad027f4106a27f54cd25bd9ed5d2680ac0607105cb1b4df71e699388c73a86279ee79f46f513e0c3ef34f9b6d5b04a3f8ba818f8ab464f9d3a98b67790f013de14b6a07b4b064e7c01958e');

/**
 * Ed25519 (RFC 8032) public key of the ARIA Registry.
 * Used to verify the classical signature on every AID.
 *
 * @remarks Can be overridden at runtime via {@link setRegistryKeys}
 * for custom registries or key rotation scenarios.
 */
export let REGISTRY_PUBLIC_KEY_ED25519: Uint8Array = hexToBytes('d4fb6d00e82aa325c71e65e7d8956dfc5f5f09d4a7fd6a34db77e269f6c471c5');

/**
 * Composite cryptographic suite identifier.
 * Both ML-DSA-65 and Ed25519 signatures must verify under this suite.
 */
export const COMPOSITE_SUITE = 'mldsa65-ed25519-2026';

/**
 * Override the embedded registry public keys at runtime.
 *
 * Use this for custom ARIA registries, key rotation scenarios,
 * or testing against a different signing authority.
 *
 * @param pqPublicKey - ML-DSA-65 public key as raw bytes
 * @param classicalPublicKey - Ed25519 public key as raw bytes (32 bytes)
 *
 * @example
 * ```typescript
 * import { setRegistryKeys } from '@aria-registry/verify';
 *
 * setRegistryKeys(myPqPublicKey, myEd25519PublicKey);
 * ```
 *
 * @since 0.1.0
 */
export function setRegistryKeys(pqPublicKey: Uint8Array, classicalPublicKey: Uint8Array): void {
  REGISTRY_PUBLIC_KEY_MLDSA65 = pqPublicKey;
  REGISTRY_PUBLIC_KEY_ED25519 = classicalPublicKey;
}
