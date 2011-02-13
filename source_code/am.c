#include "am.h"

#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>

uint8_t bool_extended = 0;
uint8_t is_authenticated = 0;

uint8_t role = 0;

uint8_t my_auth_token = 0;
uint8_t my_challenge = 0;
uint8_t my_response = 0;
uint8_t rcvd_challenge = 0;
uint8_t rcvd_response = 0;
uint8_t rcvd_auth_token = 0;

uint8_t expecting_token = 0;

uint8_t num_waits = 0;
uint32_t random_wait_time = 0;

uint8_t generated_challenge = 0;
uint8_t generated_request = 0;
uint8_t generated_auth = 0;
uint8_t tmp_response = 0;
uint32_t tmp_wait = 0;
