#ifndef  TC_USER_INCLUDED
#define  TC_USER_INCLUDED

#include <xcopy.h>
#include <burn.h>

typedef struct frame_s {
    struct frame_s *next;
    struct frame_s *prev;
    unsigned char  *frame_data;
    uint64_t        interval;
    uint32_t        seq;
    unsigned int    belong_to_the_same_req:1;
    unsigned int    frame_len:17;
    unsigned int    time_diff:14;
}frame_t;

typedef struct sess_data_s {
    frame_t *first_frame;
    frame_t *last_frame;
    long     last_pcap_time;
    uint32_t last_ack_seq;
    uint32_t frames;
    unsigned int rtt_init:1;
    unsigned int rtt_calculated:1;
    unsigned int end:1;
    unsigned int has_req:1;
    unsigned int status:10;
    unsigned int rtt:16;
}sess_data_t, *p_sess_data_t;

typedef struct sess_entry_s{
    uint64_t key;
    sess_data_t data;
    struct sess_entry_s* next;
}sess_entry_t,*p_sess_entry;

typedef struct sess_table_s{                                                                           
    int size;
    int num_of_sess;
    p_sess_entry* entries;
}sess_table_t;

typedef struct tc_user_state_s{
    uint32_t status:16;
    uint32_t timer_type:2;
    uint32_t over:1;
    uint32_t over_recorded:1;
    uint32_t timestamped:1;
    uint32_t resp_syn_received:1;
    uint32_t resp_waiting:1;
    uint32_t sess_continue:1;
    uint32_t last_ack_recorded:1;
    uint32_t evt_added:1;
    uint32_t set_rto:1;
    uint32_t snd_after_set_rto:1;
}tc_user_state_t;


typedef struct tc_user_s {
    uint64_t key;
    tc_user_state_t  state;

    uint32_t orig_clt_addr;
    uint32_t src_addr;
    uint32_t dst_addr;

    uint16_t orig_clt_port;
    uint16_t src_port;
    uint16_t dst_port;

    uint16_t wscale;
    uint32_t last_seq;
    uint32_t last_ack_seq;
    uint32_t history_last_ack_seq;
    uint32_t exp_seq;
    uint32_t exp_ack_seq;
    
    uint32_t fast_retransmit_cnt:6;
    uint32_t rtt:16;

    uint32_t ts_ec_r;
    uint32_t ts_value; 

    uint32_t srv_window;
    uint32_t total_packets_sent;

#if (TC_PCAP_SEND)
    unsigned char *src_mac;
    unsigned char *dst_mac;
#endif

    tc_event_timer_t ev;

    sess_data_t *orig_sess;
    frame_t     *orig_frame;
    frame_t     *orig_unack_frame;

    time_t   last_sent_time;
    long     last_recv_resp_cont_time;

}tc_user_t;

typedef struct tc_user_index_s {
    int index;
}tc_user_index_t;

typedef struct tc_stat_s {
    uint64_t fin_sent_cnt; 
    uint64_t rst_sent_cnt; 
    uint64_t conn_cnt; 
    uint64_t conn_reject_cnt; 
    uint64_t rst_recv_cnt; 
    uint64_t fin_recv_cnt; 
    uint64_t resp_cnt; 
    uint64_t resp_cont_cnt; 
    uint64_t active_conn_cnt; 
    uint64_t syn_sent_cnt; 
    uint64_t packs_sent_cnt; 
    uint64_t cont_sent_cnt; 
    uint64_t orig_clt_packs_cnt; 
}tc_stat_t;

extern tc_stat_t   tc_stat;

int tc_build_sess_table(int size);
bool tc_build_users(int port_prioritized, int num_users, uint32_t *ips,
        int num_ip);

uint64_t tc_get_key(uint32_t ip, uint16_t port);
tc_user_t *tc_retrieve_user(uint64_t key);
void tc_add_sess(p_sess_entry entry);
p_sess_entry tc_retrieve_sess(uint64_t key);

void process_outgress(unsigned char *packet);
bool process_ingress();
void output_stat(); 
void tc_interval_dispose(tc_event_timer_t *evt);
void release_user_resources();

#endif   /* ----- #ifndef TC_USER_INCLUDED ----- */

