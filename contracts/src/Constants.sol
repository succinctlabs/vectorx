pragma solidity 0.8.17;

uint16 constant NUM_AUTHORITIES = 76;
uint16 constant FINALITY_THRESHOLD = 7;  // This is Ceil(2/3 * NUM_AUTHORITIES)

// TwoX hash of Grandpa::CurrentSetId
bytes32 constant GRANDPA_AUTHORITIES_SETID_KEY = hex'5f9cc45b7a00c5899361e1c6099678dc8a2d09463effcc78a22d75b9cb87dffc';

// TwxX hash of System::Events
bytes32 constant SYSTEM_EVENTS_KEY = hex'26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7';

uint8 constant KEY_BYTE_LENGTH = 32;

uint8 constant NUM_CHILDREN = 16;

uint16 constant MAX_NUM_PROOF_NODES = 50; // worst case scenario, so we avoid unbounded loops

uint256 constant KEY_ADDRESS = 36;
uint256 constant PROOF_ARRAY_LEN_ADDRESS = 132;
uint256 constant PROOF_ELEMENT_START_ADDRESS_ADDRESS = 164;
uint256 constant PROOF_ELEMENT_START_ADDRESS_OFFSET = 164;


/*
Here is an example calldata layout for an invocation of the function VerifySubstrateProof

// First 4 bytes is the function signature
0   0x3221bd5c
// This is the relative start address of the proof parameter (add 4 to get the absolute address)
4	0x0000000000000000000000000000000000000000000000000000000000000080
// This is the relative start address of the key parameter (add 4 to get the absolute address)
36	0x0000000000000000000000000000000000000000000000000000000000001320
68	0xb237d8cc3098c339a59f782f9a02137cc98522ee3c7c49b73f2ff6120fabf4da
100	0x0000000000000000000000000000000000000000000000000000000000000001
// This is the array length of the proof parameter
132	0x0000000000000000000000000000000000000000000000000000000000000006
// This is the relative start address of proof[0] (add by 164 to get the absolute address)
164	0x00000000000000000000000000000000000000000000000000000000000000c0
// This is the relative start address of proof[1] (add by 164 to get the absolute address)
196	0x0000000000000000000000000000000000000000000000000000000000000d80
228	0x0000000000000000000000000000000000000000000000000000000000000de0
260	0x0000000000000000000000000000000000000000000000000000000000000e60
292	0x0000000000000000000000000000000000000000000000000000000000000f40
324	0x0000000000000000000000000000000000000000000000000000000000001140
.
.
.
// Start of the first element of the proof array.
// This is the size of that element (3222 bytes in this case).
356	0x0000000000000000000000000000000000000000000000000000000000000c96
// This is where the start of the element's data
388	0x2002140100020a00fc000000a55ed561671bb3fb0700000000000000adbbcfb3
420	0x1b478e151600000000000000000206076d6f646c70792f747273727900000000
452	0x00000000000000000000000000000000adbbcfb31b478e151600000000000000
.
.
.
3620 0x0000000000000000000000000000000000000000000000000000000000000030
3652 0x3ed41e5e16056765bc8461851072c9d7ae414b798b4d311636287745034330a1
3684 0xe71c2fa06a03c249d14d86fb7d6e942c00000000000000000000000000000000
.
.
.
3716 0x0000000000000000000000000000000000000000000000000000000000000045
3748 0x80010480392e31be566cea43139373a9dbc60ac59faeca64e2d99a663ce19ae7
.
.
.
3844 0x00000000000000000000000000000000000000000000000000000000000000a8
3876 0x80419880e2577fcd48ca94098317fc3dec8b800699eb052e90179fa4629351b6
3908 0x867980c480fc1f1fa639bef923233bbcd9fbcc86e565f52d33c5c19b238fccd2
3940 0x6dd41c2bc3809e79d25ca59c393a67acc817bbae730a26a8e173a088279c6457
3972 0x79565f5a5f2a8005beaee4aeb1f362f62d090d987e09cee98c4bbafd80427324
.
.
.
4068 0x00000000000000000000000000000000000000000000000000000000000001d1
4100 0x80eff7803df4da997913c28a77d04575813ea06b3061e55bc9ca544415ace6a9
4132 0xc336accb807544c5175425bd84ee769f8f9b0c51abd6287cbb19fa032d4114be
4164 0x4a44b1d196800ed6846e8dc9b1835c06f995123a2b1ae2f74a61597cd032c20c
4196 0x5620c3a9c0038013e6a0bb88f18eb76b71392868d85178c934e0d3110adeaa66
.
.
.
4580 0x0000000000000000000000000000000000000000000000000000000000000120
4612 0x9eaa394eea5630e07c48ae0c9558cef7398f80bb69e46863a922a4fe05e8b90c
4644 0xb7ba02854ef5b6532626aab37facdc06b2a5e480942f07c2bf423b241ab91282
4676 0xc18642e132bfacdad3862b1d3649270a42ecb4a5505f0e7b9012096b41c4eb3a
4708 0xaf947f6ea4290800004c5f0684a022a34dd8bfa2baaf44f172b710040180174d
.
.
.

// Start of the key parameter
// This is the size of the key in bytes
4900 0x0000000000000000000000000000000000000000000000000000000000000020
// This is the start of the key's data
4932 0x26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7

*/