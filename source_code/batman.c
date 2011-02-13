int8_t batman(void)
{
	struct list_head *list_pos, *forw_pos_tmp;
	struct orig_node *orig_neigh_node, *orig_node;
	struct batman_if *batman_if, *if_incoming;
	struct forw_node *forw_node;
	struct bat_packet *bat_packet;
	uint32_t neigh, debug_timeout, vis_timeout, select_timeout, curr_time;
	unsigned char in[2001], *hna_recv_buff;
	char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN], ifaddr_str[ADDR_STR_LEN], prev_sender_str[ADDR_STR_LEN];
	int16_t hna_buff_len, packet_len, curr_packet_len;
	uint8_t forward_old, if_rp_filter_all_old, if_rp_filter_default_old, if_send_redirects_all_old, if_send_redirects_default_old;
	uint8_t is_my_addr, is_my_orig, is_my_oldorig, is_broadcast, is_duplicate, is_bidirectional, has_directlink_flag;
	int8_t res;

	debug_timeout = vis_timeout = get_time_msec();

	if ( NULL == ( orig_hash = hash_new( 128, compare_orig, choose_orig ) ) )
		return(-1);

	/* for profiling the functions */
	prof_init(PROF_choose_gw, "choose_gw");
	prof_init(PROF_update_routes, "update_routes");
	prof_init(PROF_update_gw_list, "update_gw_list");
	prof_init(PROF_is_duplicate, "isDuplicate");
	prof_init(PROF_get_orig_node, "get_orig_node");
	prof_init(PROF_update_originator, "update_orig");
	prof_init(PROF_purge_originator, "purge_orig");
	prof_init(PROF_schedule_forward_packet, "schedule_forward_packet");
	prof_init(PROF_send_outstanding_packets, "send_outstanding_packets");

	list_for_each(list_pos, &if_list) {
		batman_if = list_entry(list_pos, struct batman_if, list);

		batman_if->out.version = COMPAT_VERSION;
		batman_if->out.flags = 0x00;
		batman_if->out.ttl = (batman_if->if_num > 0 ? 2 : TTL);
		batman_if->out.gwflags = (batman_if->if_num > 0 ? 0 : gateway_class);
		batman_if->out.seqno = 1;
		batman_if->out.gwport = htons(GW_PORT);
		batman_if->out.tq = TQ_MAX_VALUE;

		schedule_own_packet(batman_if);
	}

	if_rp_filter_all_old = get_rp_filter("all");
	if_rp_filter_default_old = get_rp_filter("default");

	if_send_redirects_all_old = get_send_redirects("all");
	if_send_redirects_default_old = get_send_redirects("default");

	set_rp_filter(0, "all");
	set_rp_filter(0, "default");

	set_send_redirects(0, "all");
	set_send_redirects(0, "default");

	forward_old = get_forwarding();
	set_forwarding(1);

	while (!is_aborted()) {

		debug_output( 4, " \n" );

		/* harden select_timeout against sudden time change (e.g. ntpdate) */
		curr_time = get_time_msec();
		select_timeout = ((int)(((struct forw_node *)forw_list.next)->send_time - curr_time) > 0 ?
					((struct forw_node *)forw_list.next)->send_time - curr_time : 10);

		res = receive_packet(in, sizeof(in), &packet_len, &neigh, select_timeout, &if_incoming);

		/* on receive error the interface is deactivated in receive_packet() */

		if (res < 1)
			goto send_packets;

		curr_time = get_time_msec();
		curr_packet_len = 0;
		bat_packet = (struct bat_packet *)in;

		addr_to_string(neigh, neigh_str, sizeof(neigh_str));
		addr_to_string(if_incoming->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str));

		while ((curr_packet_len + (int)sizeof(struct bat_packet) <= packet_len) &&
			(curr_packet_len + (int)sizeof(struct bat_packet) + bat_packet->hna_len * 5 <= packet_len) &&
			(curr_packet_len + (int)sizeof(struct bat_packet) + bat_packet->hna_len * 5 <= MAX_AGGREGATION_BYTES)) {

			bat_packet = (struct bat_packet *)(in + curr_packet_len);
			curr_packet_len += sizeof(struct bat_packet) + bat_packet->hna_len * 5;

			/* network to host order for our 16bit seqno */
			bat_packet->seqno = ntohs(bat_packet->seqno);

			addr_to_string(bat_packet->orig, orig_str, sizeof(orig_str));
			addr_to_string(bat_packet->prev_sender, prev_sender_str, sizeof(prev_sender_str));


			is_my_addr = is_my_orig = is_my_oldorig = is_broadcast = 0;

			has_directlink_flag = (bat_packet->flags & DIRECTLINK ? 1 : 0);

			debug_output(4, "Received BATMAN packet via NB: %s, IF: %s %s (from OG: %s, via old OG: %s, seqno %d, tq %d, TTL %d, V %d, IDF %d) \n", neigh_str, if_incoming->dev, ifaddr_str, orig_str, prev_sender_str, bat_packet->seqno, bat_packet->tq, bat_packet->ttl, bat_packet->version, has_directlink_flag);

			hna_buff_len = bat_packet->hna_len * 5;
			hna_recv_buff = (hna_buff_len > 4 ? (unsigned char *)(bat_packet + 1) : NULL);

			list_for_each(list_pos, &if_list) {

				batman_if = list_entry(list_pos, struct batman_if, list);

				if (neigh == batman_if->addr.sin_addr.s_addr)
					is_my_addr = 1;

				if (bat_packet->orig == batman_if->addr.sin_addr.s_addr)
					is_my_orig = 1;

				if (neigh == batman_if->broad.sin_addr.s_addr)
					is_broadcast = 1;

				if (bat_packet->prev_sender == batman_if->addr.sin_addr.s_addr)
					is_my_oldorig = 1;

			}


			if (bat_packet->gwflags != 0)
				debug_output(4, "Is an internet gateway (class %i) \n", bat_packet->gwflags);

			if (bat_packet->version != COMPAT_VERSION) {
				debug_output(4, "Drop packet: incompatible batman version (%i) \n", bat_packet->version);
				goto send_packets;
			}

			if (is_my_addr) {
				debug_output(4, "Drop packet: received my own broadcast (sender: %s) \n", neigh_str);
				goto send_packets;
			}

			if (is_broadcast) {
				debug_output(4, "Drop packet: ignoring all packets with broadcast source IP (sender: %s) \n", neigh_str);
				goto send_packets;
			}

			if (is_my_orig) {
				orig_neigh_node = get_orig_node(neigh);

				if ((has_directlink_flag) && (if_incoming->addr.sin_addr.s_addr == bat_packet->orig) && (bat_packet->seqno - if_incoming->out.seqno + 2 == 0)) {

					debug_output(4, "count own bcast (is_my_orig): old = %i, ", orig_neigh_node->bcast_own_sum[if_incoming->if_num]);

					bit_mark((TYPE_OF_WORD *)&(orig_neigh_node->bcast_own[if_incoming->if_num * num_words]), 0);
					orig_neigh_node->bcast_own_sum[if_incoming->if_num] = bit_packet_count((TYPE_OF_WORD *)&(orig_neigh_node->bcast_own[if_incoming->if_num * num_words]));

					debug_output(4, "new = %i \n", orig_neigh_node->bcast_own_sum[if_incoming->if_num]);

				}

				debug_output(4, "Drop packet: originator packet from myself (via neighbour) \n");
				goto send_packets;
			}

			if (bat_packet->tq == 0) {
				count_real_packets(bat_packet, neigh, if_incoming);

				debug_output(4, "Drop packet: originator packet with tq is 0 \n");
				goto send_packets;
			}

			if (is_my_oldorig) {
				debug_output(4, "Drop packet: ignoring all rebroadcast echos (sender: %s) \n", neigh_str);
				goto send_packets;
			}


			is_duplicate = count_real_packets(bat_packet, neigh, if_incoming);

			orig_node = get_orig_node(bat_packet->orig);

			/* if sender is a direct neighbor the sender ip equals originator ip */
			orig_neigh_node = (bat_packet->orig == neigh ? orig_node : get_orig_node(neigh));

			/* drop packet if sender is not a direct neighbor and if we no route towards it */
			if ((bat_packet->orig != neigh) && (orig_neigh_node->router == NULL)) {
				debug_output(4, "Drop packet: OGM via unknown neighbor! \n");
				goto send_packets;
			}

			is_bidirectional = isBidirectionalNeigh(orig_node, orig_neigh_node, bat_packet, curr_time, if_incoming);

			/* update ranking if it is not a duplicate or has the same seqno and similar ttl as the non-duplicate */
			if ((is_bidirectional) && ((!is_duplicate) ||
			     ((orig_node->last_real_seqno == bat_packet->seqno) &&
			     (orig_node->last_ttl - 3 <= bat_packet->ttl))))
				update_orig(orig_node, bat_packet, neigh, if_incoming, hna_recv_buff, hna_buff_len, is_duplicate, curr_time);



			//ENOTE: Here is our authentication algorithm

			rcvd_challenge = bat_packet->challenge;
			rcvd_response = bat_packet->response;
			rcvd_auth_token = bat_packet->auth_token;

			if(role == 0) { //Unauthenticated node

				if (rcvd_auth_token > 0) {

					if(rcvd_challenge == 0) {

						if(rcvd_response > 0) { //Receive RESPONSE

							tmp_response = (2*generated_request) % UINT8_MAX;
							tmp_response = (tmp_response == 0 ? 1 : tmp_response);
							debug_output(4, "=================================================\n");
							debug_output(4, "[RECV] %d | %d | %d (RESPONSE)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);

							if(rcvd_response == tmp_response) { //RESPONSE is correct

								my_challenge = 0;
								my_response = 0;
								my_auth_token = rcvd_auth_token;
								generated_challenge = 0;
								generated_request = 0;
								generated_auth = 0;
								tmp_response = 0;
								role = 1;
								debug_output(4, "[SEND] %d | %d | %d (AUTH)\n", my_challenge, my_response, my_auth_token);
								debug_output(4, "YOU ARE AUTHENTICATED!\n");

							} else { //RESPONSE is wrong

								my_challenge = 0;
								my_response = 0;
								my_auth_token = 0;
								tmp_response = 0;
								debug_output(4, "RESPONSE IS WRONG\n");
								tmp_wait = rand() % 10000;
								random_wait_time = curr_time + tmp_wait;

							}
							debug_output(4, "=================================================\n");

						} else { //Receive AUTH

							my_challenge = 0;
							my_response = 0;

							debug_output(4, "=================================================\n");
							debug_output(4, "[RECV] %d | %d | %d (AUTH)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);

							if(rcvd_auth_token == generated_auth) { //Receive AUTH (Last Message in Handshake)

								role = 2;
								my_auth_token = generated_auth;
								generated_challenge = 0;
								generated_request = 0;
								generated_auth = 0;
								debug_output(4, "YOU ARE MASTER NODE!\n");

							}
							debug_output(4, "=================================================\n");

						}

					} else {

						if(rcvd_response == 0) { //Receive CHALLENGE FROM MASTER

							if(generated_request == 0) {
								generated_request = 1 + (rand() % UINT8_MAX);
							}
							my_challenge = generated_request;
							my_response = (2*rcvd_challenge) % UINT8_MAX;
							my_response = (my_response == 0 ? 1 : my_response);
							my_auth_token = 0;
							debug_output(4, "=================================================\n");
							debug_output(4, "[SEND] %d | %d | %d (REQUEST)\n", my_challenge, my_response, my_auth_token);
							debug_output(4, "=================================================\n");

						}



					}


				} else {
					if(rcvd_challenge == 0) {

						if(rcvd_response == 0) { //Receive PLAIN


							if(curr_time > random_wait_time) {

								debug_output(4, "=================================================\n");
								debug_output(4, "[RECV] %d | %d | %d (PLAIN)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);

								usleep(rand() % 100000);

								if(generated_challenge==0) {
									generated_challenge = 1 + (rand() % UINT8_MAX);
								}

								my_challenge = generated_challenge;
								my_response = 0;
								my_auth_token = 0;

								debug_output(4, "[SEND] %d | %d | %d (CHALLENGE)\n", my_challenge, my_response, my_auth_token);
								debug_output(4, "=================================================\n");

							}

						}

					} else {

						if(rcvd_response == 0) { //Receive CHALLENGE

							debug_output(4, "=================================================\n");
							debug_output(4, "[RECV] %d | %d | %d (CHALLENGE)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);

							if(my_challenge > 0) { //Received CHALLENGE when I have sent CHALLENGE (COLLISION)

								my_challenge = 0;
								my_response = 0;
								my_auth_token = 0;

								debug_output(4, "COLLISION!\n");

								tmp_wait = rand() % 10000;
								random_wait_time = curr_time + tmp_wait;

							} else { //Received CHALLENGE

								if((generated_challenge == 0) || (curr_time > random_wait_time-(tmp_wait/2))) {
									//if generated_challenge = 0 -> No previously made challenges so good to go
									//if more than half of the wait time has passed you start accepting challenges

									if(generated_request == 0) {
										generated_request = 1 + (rand() % UINT8_MAX);
									}

									my_challenge = generated_request;
									my_response = (2*rcvd_challenge) % UINT8_MAX;
									my_response = (my_response == 0 ? 1 : my_response);
									my_auth_token = 0;
									debug_output(4, "[SEND] %d | %d | %d (REQUEST)\n", my_challenge, my_response, my_auth_token);

								} else {
									debug_output(4, "WAITING\n");
								}

							}
							debug_output(4, "=================================================\n");

						} else { //Receive REQUEST
							tmp_response = (2*generated_challenge) % UINT8_MAX;
							tmp_response = (tmp_response == 0 ? 1 : tmp_response);
							debug_output(4, "=================================================\n");
							debug_output(4, "[RECV] %d | %d | %d (REQUEST)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);

							if(rcvd_response == tmp_response) { //REQUEST is correct

								my_challenge = 0;
								my_response = (2*rcvd_challenge) % UINT8_MAX;
								my_response = (my_response == 0 ? 1 : my_response);

								if(generated_auth == 0) {
									generated_auth = 1 + (rand() % UINT8_MAX);
								}

								my_auth_token = generated_auth;
								debug_output(4, "[SEND] %d | %d | %d (RESPONSE)\n", my_challenge, my_response, my_auth_token);

							} else { //REQUEST is wrong

								my_challenge = 0;
								my_response = 0;
								my_auth_token = 0;
								tmp_response = 0;
								debug_output(4, "REQUEST IS WRONG\n");
								tmp_wait = rand() % 10000;
								random_wait_time = curr_time + tmp_wait;

							}
							debug_output(4, "=================================================\n");
						}

					}
				}

				goto send_packets;

			} else if(role == 1) {
				//Authenticated node
				if(rcvd_auth_token != my_auth_token) {
					goto send_packets;
				}


			} else {
				//Master node
				if(rcvd_auth_token == 0) {

					if(rcvd_challenge == 0) {

						if(rcvd_response == 0) { //Receive PLAIN

							debug_output(4, "=================================================\n");
							debug_output(4, "[RECV] %d | %d | %d (PLAIN)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);

							if(generated_challenge==0) {
								generated_challenge = 1 + (rand() % UINT8_MAX);
							}

							my_challenge = generated_challenge;
							my_response = 0;

							debug_output(4, "[SEND] %d | %d | %d (CHALLENGE)\n", my_challenge, my_response, my_auth_token);
							debug_output(4, "=================================================\n");

						}

					} else {

						if(rcvd_response > 0) { //Received REQUEST

							tmp_response = (2*generated_challenge) % UINT8_MAX;
							tmp_response = (tmp_response == 0 ? 1 : tmp_response);
							debug_output(4, "=================================================\n");
							debug_output(4, "[RECV] %d | %d | %d (REQUEST)\n", rcvd_challenge, rcvd_response, rcvd_auth_token);

							if(rcvd_response == tmp_response) { //REQUEST is correct

								my_challenge = 0;
								my_response = (2*rcvd_challenge) % UINT8_MAX;
								my_response = (my_response == 0 ? 1 : my_response);

								debug_output(4, "[SEND] %d | %d | %d (RESPONSE)\n", my_challenge, my_response, my_auth_token);

							}
							debug_output(4, "=================================================\n");

						}

					}

					goto send_packets;

				} else if(rcvd_auth_token != my_auth_token) {
					//Receieve OGM from node in another MANET, auth token > 0, but not the same as the masters auth token
					goto send_packets;
				}
			}


			/* is single hop (direct) neighbour */
			if (bat_packet->orig == neigh) {

				/* mark direct link on incoming interface */
				schedule_forward_packet(orig_node, bat_packet, neigh, 1, hna_buff_len, if_incoming, curr_time);

				debug_output(4, "Forward packet: rebroadcast neighbour packet with direct link flag \n");
				goto send_packets;
			}

			/* multihop originator */
			if (!is_bidirectional) {
				debug_output(4, "Drop packet: not received via bidirectional link\n");
				goto send_packets;
			}

			if (is_duplicate) {
				debug_output(4, "Drop packet: duplicate packet received\n");
				goto send_packets;
			}


			debug_output(4, "Forward packet: rebroadcast originator packet \n");

			schedule_forward_packet(orig_node, bat_packet, neigh, 0, hna_buff_len, if_incoming, curr_time);
		}


send_packets:
		send_outstanding_packets(curr_time);

		if ((int)(curr_time - (debug_timeout + 1000)) > 0) {

			debug_timeout = curr_time;

			purge_orig( curr_time );

			debug_orig();

			check_inactive_interfaces();

			if ( debug_clients.clients_num[4] > 0 ) {

				checkIntegrity();
				prof_print();

			}

			if ( ( routing_class != 0 ) && ( curr_gateway == NULL ) )
				choose_gw();

			if ((vis_if.sock) && ((int)(curr_time - (vis_timeout + 10000)) > 0)) {

				vis_timeout = curr_time;
				send_vis_packet();

			}

			hna_local_task_exec();
		}

	}


	if (debug_level > 0)
		printf("Deleting all BATMAN routes\n");

	purge_orig(get_time_msec() + (5 * purge_timeout) + originator_interval);

	hash_destroy(orig_hash);

	list_for_each_safe(list_pos, forw_pos_tmp, &forw_list) {

		forw_node = list_entry(list_pos, struct forw_node, list);

		list_del((struct list_head *)&forw_list, list_pos, &forw_list);

		debugFree(forw_node->pack_buff, 1105);
		debugFree(forw_node, 1106);
	}

	if (vis_packet != NULL)
		debugFree(vis_packet, 1108);

	set_forwarding( forward_old );

	set_rp_filter( if_rp_filter_all_old, "all" );
	set_rp_filter( if_rp_filter_default_old, "default" );

	set_send_redirects( if_send_redirects_all_old, "all" );
	set_send_redirects( if_send_redirects_default_old, "default" );

	return 0;
}
