pragma solidity 0.8.17;

uint16 constant NUM_AUTHORITIES = 10;
uint16 constant FINALITY_THRESHOLD = 7;  // This is Ceil(2/3 * NUM_AUTHORITIES)

// TwoX hash of Grandpa::CurrentSetId
bytes constant GRANDPA_AUTHORITIES_SETID_KEY = hex'5f9cc45b7a00c5899361e1c6099678dc8a2d09463effcc78a22d75b9cb87dffc';

// TwxX hash of System::Events
bytes constant SYSTEM_EVENTS_KEY = hex'26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7';