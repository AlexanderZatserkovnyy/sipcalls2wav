/* tap-rtp.cpp
 * RTP SAVE TAP for tshark
 * 
 * Copyright 2017
 * By Alexander Zatserkovnyy (avz651@gmail.com)
 *
/*
 * This TAP save RTP streams to pcap and to payload files
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include <locale.h>
#include <glib.h>
#include <arpa/inet.h>

#include <epan/packet_info.h>
#include <epan/value_string.h>
#include <epan/tap.h>
#include <wiretap/wtap.h>
#include <epan/rtp_pt.h>
#include <epan/stat_tap_ui.h>
#include <epan/addr_resolv.h>
#include <epan/addr_resolv.h>
#include <epan/proto_data.h>
#include <epan/epan_dissect.h> //
#include "epan/dissectors/packet-sip.h"
#include "epan/dissectors/packet-sdp.h"
#include "epan/dissectors/packet-rtp.h"
#include "epan/dissectors/packet-rtp-events.h"
#include "epan/dissectors/packet-t38.h"

typedef struct _sip_calls_t {
	GHashTable*  pcap_files;    // key - call id, value - file handler
        GHashTable*  sdp_frames;    // key - frame number, value - call id
	GHashTable*  payload_files; // key - string (?) call_id + ssrc + payload_type + setupframe (?) 
        guint32	     frame_num;
        gchar*       call_id;
	gboolean     is_registered;
} sip_calls_t;

static sip_calls_t sip_calls;

void register_tap_listener_rtp_save(void);

static int hfid_sip_cseq_method = -1;    //"sip.CSeq.method"
static int hfid_sip_to_tag = -1;         //"sip.to.tag"

static void
sip_reset_hash_pcap_files(gchar *key _U_ , wtap_dumper* dh, gpointer ptr _U_ )
{       
    int   err;
    if(dh){
      wtap_dump_flush(dh);
      if(!wtap_dump_close(dh, &err)) printf("Error: %s\n",g_strerror(err));
    }
}

static void
sip_reset_hash_sdp_frames(gint *key _U_ , gchar* call_id, gpointer ptr _U_ )
{
    if(call_id) g_free(call_id); 
}

static void
sip_reset_hash_payload_files(gchar *key _U_ , FILE* ph, gpointer ptr _U_ )
{    
    if(ph){
      fflush(ph);
      if(fclose(ph)==EOF) printf("Error: %s\n",g_strerror(errno));
    }
}

gboolean 
sdp_rm_vals(gpointer key, gpointer value, gpointer call_id) {
    if( g_strcmp0((gchar*) call_id,(gchar*) value)==0 ){
      if(value) g_free(value);
      if(key) g_free(key);
      return TRUE; 
    }else return FALSE;
}

gboolean 
payload_rm_vals(gpointer key, gpointer value, gpointer data) {
    gchar* call_id = (gchar*) data;
    gchar* filename = (gchar*) key;
    guint  call_id_len = strlen(call_id);
    if( call_id && filename && strncmp((gchar*) call_id,(gchar*) filename, call_id_len)==0 ){
      FILE* ph = (FILE*) value;
      fflush(ph);
      fclose(ph);
      g_free(filename);
      return TRUE; 
    }else return FALSE;
}

void dump_packet(wtap_dumper* d, packet_info *p ) {
  int err=0;
  gchar *err_info;
  struct wtap_pkthdr pkthdr;
  struct data_source *data_src;
  const guchar* data;
  tvbuff_t* tvb;

  data_src = (struct data_source*) p->data_src->data;
  tvb = get_data_source_tvb(data_src);
  memset(&pkthdr, 0, sizeof(pkthdr));
  pkthdr.rec_type = REC_TYPE_PACKET;
  pkthdr.presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
  pkthdr.ts        = p->abs_ts;
  pkthdr.len       = tvb_reported_length(tvb);
  pkthdr.caplen    = tvb_captured_length(tvb);
  pkthdr.pkt_encap = p->pkt_encap;
  pkthdr.pseudo_header = *p->pseudo_header;
  data = (const guchar *)tvb_memdup(wmem_packet_scope(),tvb,0,pkthdr.caplen);
  wtap_dump(d, &pkthdr, data, &err, &err_info);
  if(err){
      printf("%s\n",err_info);
      g_free(err_info);
      exit(1);
  }
}


////////////////////////////////// a packet /////////////////////////////////////////////////////////

static gboolean
rtpsave_sip_packet(void *arg _U_, packet_info *pinfo, epan_dissect_t *edt, void const *sip_info_ptr)
{
    sip_calls_t *tapinfo = (sip_calls_t *) arg;

    const sip_info_value_t *sipinfo = (const sip_info_value_t *)sip_info_ptr;
    //
    //
    if(sipinfo->tap_call_id==NULL) return FALSE;
    // dump the packet to pcap and make the call setups if needed
    guint32 frame_number= pinfo->num;
    guint    response_code=sipinfo->response_code;
    guint32  cseq_number=sipinfo->tap_cseq_number;
    gchar   *request_method =g_strdup(sipinfo->request_method);
    gchar   *call_id=g_strdup(sipinfo->tap_call_id);//don't free it here!
    gchar   *from_addr=g_strdup(sipinfo->tap_from_addr);;
    gchar   *to_addr=g_strdup(sipinfo->tap_to_addr);
    gchar   *reason_phrase=g_strdup(sipinfo->reason_phrase);
    gboolean good_invite = FALSE;
    int      err = 0;

    tapinfo->frame_num = frame_number;
    if(tapinfo->call_id) {
       if(strcmp(tapinfo->call_id,sipinfo->tap_call_id)!=0){
          g_free(tapinfo->call_id);
          tapinfo->call_id=g_strdup(sipinfo->tap_call_id);
       }
    }else tapinfo->call_id=g_strdup(sipinfo->tap_call_id);
    
    if( request_method && (strcmp(sipinfo->request_method,"INVITE")==0) ){ //
        GPtrArray *gp;
	gp=proto_get_finfo_ptr_array(edt->tree, hfid_sip_to_tag);
	if(!gp) good_invite = TRUE;
    } 

    wtap_dumper* wd = (wtap_dumper*) g_hash_table_lookup(tapinfo->pcap_files,call_id); 
    if( good_invite && !(wd) ) { //initialize storage,insert to db,...
       int filetype = WTAP_FILE_TYPE_SUBTYPE_PCAP;
       int encap = WTAP_ENCAP_ETHERNET;

       gchar* filename = g_strconcat("/data/pcaps1/",call_id,".pcap",NULL);
       wd = wtap_dump_open(filename, filetype, encap, 0, FALSE, &err);
       if(err){
       	  printf("Error: %s\n",wtap_strerror(err));
	  exit(1);
       }
       g_free(filename);
       g_hash_table_insert(tapinfo->pcap_files,call_id,wd); 
      /* SQL SELECT , INSERT (INVITE) */
       printf("INVITE SIP frame: %u; ",frame_number);
       printf("request method: %s; ",request_method);
       printf("cseq_number: %u; ",cseq_number);
       printf("call_id: %s\n",call_id);
    }
    
    if(wd){
     dump_packet(wd,pinfo);

     if(response_code!=0){
        GPtrArray *gp;
        gp=proto_get_finfo_ptr_array(edt->tree, hfid_sip_cseq_method);
        if(gp && gp->len==1){
          field_info *fi;
          char *cseq_method;
          fi=(field_info *)gp->pdata[0];
          cseq_method=fi->value.value.string;
          if( (response_code==200 && ( strcmp(cseq_method,"BYE")==0 || strcmp(cseq_method,"CANCEL")==0 )) ||
	      (response_code==487 && strcmp(cseq_method,"INVITE")==0) )
	  {
            wtap_dump_flush(wd);
            if(!wtap_dump_close(wd, &err)){
 	       printf("Error: %s\n",g_strerror(err));
	    }
            g_hash_table_remove(tapinfo->pcap_files,call_id); //?
	    g_hash_table_foreach_remove(tapinfo->sdp_frames,(GHRFunc)sdp_rm_vals,call_id);
            g_hash_table_foreach_remove(tapinfo->payload_files,(GHRFunc)payload_rm_vals,call_id);

           /* SQL UPDATE (the call state , 200 reply to BYE/CANSEL or 487 to INVITE) */
            printf("BYE/CANSEL SIP frame: %u; ",frame_number);
            printf("response code: %u - %s; ",response_code,reason_phrase);
            printf("cseq_number: %u; ",cseq_number);
            printf("cseq method: %s; ",cseq_method);
            printf("call_id: %s\n",call_id);
	  } 
        }
      }
    }
  
    g_free(request_method);
    //g_free(call_id);
    g_free(from_addr);
    g_free(to_addr);
    g_free(reason_phrase);

    return FALSE;
}

static gboolean
rtpsave_sdp_packet(void *arg _U_, packet_info *pinfo, epan_dissect_t *edt, void const *sdp_info_ptr)
{  
    sip_calls_t *tapinfo = (sip_calls_t *)arg;
    guint32 frame_number= pinfo->num;

    if( frame_number==tapinfo->frame_num && tapinfo->call_id ){
      gchar* call_id = g_strdup(tapinfo->call_id);
      gint *fr_num_key=g_new(gint, 1);
      *fr_num_key = frame_number;
      g_hash_table_insert(tapinfo->sdp_frames,fr_num_key,call_id);
      /* printf("SDP frame: %u; SIP frame: %u; CallID: %s ",frame_number,tapinfo->frame_num, tapinfo->call_id); */
    }
    return FALSE;
}

static gboolean
rtpsave_packet(void *arg _U_, packet_info *pinfo, epan_dissect_t *edt, void const *rtp_info_ptr)
{
    sip_calls_t *tapinfo = (sip_calls_t *)arg;

    const struct _rtp_info *rtpinfo = (const struct _rtp_info *)rtp_info_ptr;
    guint32 ssrc=rtpinfo->info_sync_src;
    guint32 frame_number= pinfo->num;
    guint16 seq_num=rtpinfo->info_seq_num;
    guint8  payload_type = rtpinfo->info_payload_type;
    guint32 setup_frame_num=rtpinfo->info_setup_frame_num;

    gchar* call_id  = (gchar*) g_hash_table_lookup(tapinfo->sdp_frames,&setup_frame_num);
    if(call_id==NULL){
       printf("Can't find SDP/SIP data for the RTP frame:%d, SDP frame:%d\n",frame_number, setup_frame_num);
       return FALSE;
    } 

    wtap_dumper* wd = (wtap_dumper*) g_hash_table_lookup(tapinfo->pcap_files,call_id); 
    if(!wd){
       printf("Can't find PCAP file handler for the RTP frame:%d, SDP frame:%d\n",frame_number, setup_frame_num);
       return FALSE;
    }
    //// save the packet to pcap file
    dump_packet(wd,pinfo);
    //
    //// save the packet payload to a file
    //make payload filename 
    gchar* filename = g_strdup_printf("/data/pcaps1/%s_%d.%d",call_id,ssrc,payload_type);
    FILE* payload_file = (FILE *) g_hash_table_lookup(tapinfo->payload_files,filename);
    if(!payload_file){
        payload_file = fopen(filename, "wb");
	if (payload_file == NULL){
	    printf("Error: %s\n",g_strerror(errno));
	    exit(1);
	}
	g_hash_table_insert(tapinfo->payload_files,filename,payload_file);
    }

    const guint8* payload_data=rtpinfo->info_data + rtpinfo->info_payload_offset;
    guint32 payload_len=rtpinfo->info_payload_len-rtpinfo->info_padding_count;

    if(payload_file && payload_len && rtpinfo->info_data && payload_data){
      size_t nchars;
      nchars=fwrite(payload_data, sizeof(unsigned char), payload_len, payload_file);
      if(nchars != payload_len) printf("Error: a write error %s \n",g_strerror(errno));
    }
    guint32 payload_firstbytes=0;
    guint32 payload_lastbytes=0;
    memcpy(&payload_firstbytes,payload_data,sizeof(payload_firstbytes));
    memcpy(&payload_lastbytes,payload_data+(payload_len-sizeof(payload_firstbytes)),sizeof(payload_firstbytes));

    return FALSE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////

static void
rtpsave_draw(void *arg _U_)
{
    printf("=====RTP=====\n");
    sip_calls_t *calls = (sip_calls_t *) arg; 
    g_hash_table_foreach( calls->pcap_files, (GHFunc)sip_reset_hash_pcap_files, NULL);
    g_hash_table_foreach( calls->sdp_frames, (GHFunc)sip_reset_hash_sdp_frames, NULL);
    g_hash_table_foreach( calls->payload_files, (GHFunc)sip_reset_hash_payload_files, NULL);
    return; 
}

static void
rtpsave_sip_draw(void *arg _U_)
{
    printf("=====SIP=====\n");
    return; 
}

static void
rtpsave_reset(void *arg _U_)
{
    sip_calls_t *calls = (sip_calls_t *) arg; 
    g_hash_table_foreach( calls->pcap_files, (GHFunc)sip_reset_hash_pcap_files, NULL);
    g_hash_table_foreach( calls->sdp_frames, (GHFunc)sip_reset_hash_sdp_frames, NULL);
    g_hash_table_foreach( calls->payload_files, (GHFunc)sip_reset_hash_payload_files, NULL);
    return;
}


static void
rtpsave_sip_reset(void *arg _U_)
{
    return;
}
//
static void
rtp_save_init(const char *opt_arg _U_, void *userdata _U_)
{
    hfid_sip_cseq_method = proto_registrar_get_id_byname("sip.CSeq.method");
    hfid_sip_to_tag = proto_registrar_get_id_byname("sip.to.tag");
    sip_calls.frame_num=0;   
 
    GString             *err_p1, *err_p2, *err_p3;
    

    err_p1 = register_tap_listener("rtp", &sip_calls, NULL, 0, rtpsave_reset, rtpsave_packet, rtpsave_draw);
    if (err_p1 != NULL)
    {
        g_string_free(err_p1, TRUE);
        exit(1);
    }

    err_p2 = register_tap_listener("sip", &sip_calls, "sip and !(sip.CSeq.method == REGISTER) and !(sip.CSeq.method == OPTIONS) and (sip.to.tag or !sip.to.tag)", 0,
            rtpsave_sip_reset, rtpsave_sip_packet, rtpsave_sip_draw);
    if (err_p2 != NULL)
    {
        g_string_free(err_p2, TRUE);
        exit(1);
    }

    err_p3 = register_tap_listener("sdp", &sip_calls, NULL, 0, NULL, rtpsave_sdp_packet, NULL);
    if (err_p3 != NULL)
    {
        g_string_free(err_p3, TRUE);
        exit(1);
    }

    sip_calls.pcap_files=g_hash_table_new(g_str_hash, g_str_equal);
    sip_calls.sdp_frames=g_hash_table_new(g_int_hash, g_int_equal);
    sip_calls.payload_files=g_hash_table_new(g_str_hash, g_str_equal);
}

static stat_tap_ui rtp_save_stat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "rtp,save",
    rtp_save_init,
    0,
    NULL
};

void
remove_tap_listener_rtp_stream(sip_calls_t *tapinfo)
{
    if (tapinfo && tapinfo->is_registered) {
        remove_tap_listener(tapinfo);
        tapinfo->is_registered = FALSE;
    }
}

void
register_tap_listener_rtp_save(void)
{
    register_stat_tap_ui(&rtp_save_stat_ui, NULL);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
