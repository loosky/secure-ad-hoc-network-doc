#ifndef AM_H
#define AM_H

#include "batman.h"

extern uint8_t role; // Unauthenticated = 0, Authenticated = 1, Master = 2

extern uint8_t my_challenge; // 0 if no challenge to send
extern uint8_t my_response; // 0 if no response to send
extern uint8_t my_auth_token; // 0 if not authenticated
extern uint8_t tmp_response; // used for response calc.
extern uint8_t generated_challenge; // Verify received response in Request
extern uint8_t generated_request; // Verify received Response
extern uint8_t generated_auth;

extern uint8_t rcvd_challenge; // Received Challenge, 0 if no challenge
extern uint8_t rcvd_response; // Received Response Value, 0 if no response
extern uint8_t rcvd_auth_token;	// 0 if not authenticated
extern uint8_t expecting_token;	// Expected Value of received auth token

extern uint32_t	random_wait_time; // tmp_wait + curr_time
extern uint32_t tmp_wait; // Random backoff time value

#endif
