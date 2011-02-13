75:	//ENOTE: Here we add challenge response authentication values to the OGM if they are set, node
76:	((struct bat_packet *)forw_node_new->pack_buff)->challenge = my_challenge;
78:	((struct bat_packet *)forw_node_new->pack_buff)->response = my_response;
79:	((struct bat_packet *)forw_node_new->pack_buff)->auth_token = my_auth_token;
