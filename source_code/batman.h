struct bat_packet
{
	uint8_t  version;  /* batman version field */
	uint8_t  flags;    /* 0x80: UNIDIRECTIONAL link, 0x40: DIRECTLINK flag, ... */
	uint8_t  ttl;
	uint8_t  gwflags;  /* flags related to gateway functions: gateway class */
	uint16_t seqno;
	uint16_t gwport;
	uint32_t orig;
	uint32_t prev_sender;
	uint8_t tq;
	uint8_t hna_len;
	//ENOTE: challenge=0 -> "no challenge".
	uint8_t challenge;
	//ENOTE: response=0 -> "no response".
	uint8_t response;
	//ENOTE: auth_token=0 -> "not authenticated".
	uint8_t auth_token;
} __attribute__((packed));
