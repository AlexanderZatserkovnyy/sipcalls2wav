/* tap-rtp.cpp
 * RTP SAVE TAP for tshark
 * 
 * Copyright 2017
 * By Alexander Zatserkovnyy (avz651@gmail.com)
 *
 *
 * This TAP save RTP streams to pcap and to payload files
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <locale.h>
#include <glib.h>
#include <arpa/inet.h>
#include <unistd.h>

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
#include <libpq-fe.h>

#define PATH_TO_CONF "/data/conf/tap-rtpsave.conf" 

typedef struct _call_rec_t {
        nstime_t     pkt_ts;
        wtap_dumper* wd;
	FILE*        ch1_pipe;
	FILE*        ch2_pipe;
	gboolean     opened;
	gboolean     live;
	gint64       first_pld_sdp_frame;
        address      src_ip;
} call_rec_t;

typedef struct _payload_file_t {
        nstime_t  pkt_ts;
        FILE*     ph;
        PGconn*   conn;
	gboolean  caller;
} payload_file_t;

typedef struct _sip_calls_t {
	GHashTable*  calls;         // key - call id, value - file handler
        GHashTable*  sdp_frames;    // key - frame number, value - call id
	GHashTable*  payload_files; // key - string (?) call_id + ssrc + payload_type + setupframe (?) 
        guint32	     frame_num;
        gchar*       call_id;
	gboolean     is_registered;
	nstime_t     pkt_ts;
        PGconn*      conn;
	gchar*       path_to_storage;
	gchar*       ch1_live_cmd;
        gchar*       ch2_live_cmd;
	gboolean     requested_calls_only;
	gdouble      call_timout;
	gboolean     write_full_opened;
	gboolean     debug;
} sip_calls_t;

static sip_calls_t sip_calls;

void register_tap_listener_rtp_save(void);

static int hfid_sip_cseq_method = -1;    //"sip.CSeq.method"
static int hfid_sip_to_tag = -1;         //"sip.to.tag"

void exiterror(char *mess)
{
  fprintf(stderr, "%s\n", mess);
  exit(1);
}

gchar* clear_sipaddr( gchar* addr ){
   char* b=strchr(addr,'<');
   if(b) b++;
   else b=addr;
   char* e=strchr(b,';');
   return g_strndup(b, (e) ? (size_t) (e - b) : strlen(b) );
} 

static const gchar *
get_tzname(struct tm *tmp)
{
# if defined(HAVE_STRUCT_TM_TM_ZONE)
        return tmp->tm_zone;
# else /* HAVE_STRUCT_TM_TM_ZONE */
        if ((tmp->tm_isdst != 0) && (tmp->tm_isdst != 1)) {
                return "???";
        }
#  if defined(HAVE_TZNAME)
        return tzname[tmp->tm_isdst];
#  else
        return tmp->tm_isdst ? "?DT" : "?ST";
#  endif /* HAVE_TZNAME */
# endif /* HAVE_STRUCT_TM_TM_ZONE */
}

gchar* 
my_abs_time_to_str(const nstime_t *abs_time)
{
    gchar *buf = NULL;
    struct tm *tmp = NULL;
    const char *zonename = "???";
    tmp = localtime(&abs_time->secs);
    if (tmp){
         zonename = get_tzname(tmp);
         buf = wmem_strdup_printf(NULL, "%4d-%02d-%02d %02d:%02d:%02d.%03ld%s",
                                                        tmp->tm_year + 1900,
                                                        tmp->tm_mon+1,
                                                        tmp->tm_mday,
                                                        tmp->tm_hour,
                                                        tmp->tm_min,
                                                        tmp->tm_sec,
                                                        (long)abs_time->nsecs/1000000,
                                                        zonename);
   } else buf = wmem_strdup(NULL, "Not representable time");
   return buf;
}

static void
sip_reset_hash_calls(gchar *key _U_ , call_rec_t* call, sip_calls_t* tapinfo _U_ )
{       
    int err;
    if( call && call->wd ){
      wtap_dump_flush(call->wd);
      if(!wtap_dump_close(call->wd, &err)) fprintf(stderr,"%s\n",g_strerror(err));
      if(call->live){
        if(call->ch1_pipe) pclose(call->ch1_pipe);
        if(call->ch2_pipe) pclose(call->ch2_pipe);
      }
      if(&(call->src_ip)) free_address(&(call->src_ip));
    }
    if( key && call && tapinfo->conn ){
      PGresult* res;
      gchar* ts_buf = my_abs_time_to_str(&(call->pkt_ts));
      gchar* sqlrequest;
      sqlrequest=g_strdup_printf("UPDATE cdr SET disposition='UNCLOSED',duration=EXTRACT(SECOND FROM ( '%s'- calldate )) WHERE clid='%s';",
                                  ts_buf, key);
      res = PQexec(tapinfo->conn,sqlrequest);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) exiterror(PQresultErrorMessage(res));
      PQclear(res);
      g_free(sqlrequest);
      wmem_free(NULL,ts_buf);
    }
    g_free(call);
}

static void
sip_reset_hash_payload_files(gchar *key _U_ , payload_file_t* pf, gpointer ptr _U_ )
{   
    if(pf && pf->ph){
      fflush(pf->ph);
      if(fclose(pf->ph)==EOF) fprintf(stderr,"%s\n",g_strerror(errno));
      PGresult* res;
      gchar* ts_buf = my_abs_time_to_str(&(pf->pkt_ts));
      gchar* sqlrequest;
      sqlrequest=g_strdup_printf("UPDATE files SET f_closed='%s' WHERE filename='%s';", ts_buf, key);
      res = PQexec(pf->conn,sqlrequest);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) exiterror(PQresultErrorMessage(res));
      PQclear(res);
      g_free(sqlrequest);
      wmem_free(NULL,ts_buf);
    }
    g_free(pf);
}

gboolean 
sdp_rm_vals(gpointer key _U_, gpointer value, gpointer call_id) 
{   
    if( g_strcmp0((gchar*) call_id,(gchar*) value)==0 ){
      return TRUE; 
    }else return FALSE;
}

gboolean 
payload_rm_vals(gpointer key, gpointer value, gpointer data) 
{
    gchar* call_id = (gchar*) data;
    gchar* filename = (gchar*) key;
    guint  call_id_len = strlen(call_id);
    if( call_id && filename && strncmp((gchar*) call_id,(gchar*) filename, call_id_len)==0 ){
      payload_file_t* pf = (payload_file_t*) value;
      fflush(pf->ph);
      fclose(pf->ph);
      PGresult* res;
      gchar* ts_buf = my_abs_time_to_str(&(pf->pkt_ts));
      gchar* sqlrequest;
      sqlrequest=g_strdup_printf("UPDATE files SET f_closed='%s' WHERE filename='%s';", ts_buf, filename);
      res = PQexec(pf->conn,sqlrequest);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) exiterror(PQresultErrorMessage(res));
      PQclear(res);
      g_free(sqlrequest);
      wmem_free(NULL,ts_buf);

      g_free(pf);
      return TRUE; 
    }else 
      return FALSE;
}

gboolean
rm_calls_by_timeout(gpointer key, gpointer value, gpointer data)
{
   sip_calls_t* tapinfo = (sip_calls_t *) data;
   gchar*       call_id = (gchar *) key;
   call_rec_t*  call = (call_rec_t*) value;
   double       time_diff =fabs(nstime_to_sec(&(tapinfo->pkt_ts))-nstime_to_sec(&(call->pkt_ts)));
   if( time_diff > tapinfo->call_timout ){
     int err;
     if( call_id && call ){
       if(call->wd){ 
          wtap_dump_flush(call->wd);
          if(!wtap_dump_close(call->wd, &err)) fprintf(stderr,"%s\n",g_strerror(err));
	  if(call->live){
	    if(call->ch1_pipe) pclose(call->ch1_pipe);
            if(call->ch2_pipe) pclose(call->ch2_pipe);
	  }
	  if(&(call->src_ip)) free_address(&(call->src_ip));
          g_hash_table_foreach_remove(tapinfo->payload_files,(GHRFunc)payload_rm_vals,call_id);
       }
       g_hash_table_foreach_remove(tapinfo->sdp_frames,(GHRFunc)sdp_rm_vals,call_id);
       if( tapinfo->conn ){
          PGresult* res;
          gchar* ts_buf = my_abs_time_to_str(&(call->pkt_ts));
          gchar* sqlrequest;
          sqlrequest=g_strdup_printf("UPDATE cdr SET disposition='UNCLOSED',duration=EXTRACT(SECOND FROM ( '%s'- calldate )) WHERE clid='%s';",
                                       ts_buf, call_id);
          res = PQexec(tapinfo->conn,sqlrequest);
          if (PQresultStatus(res) != PGRES_COMMAND_OK) exiterror(PQresultErrorMessage(res));
          PQclear(res);
          g_free(sqlrequest);
          wmem_free(NULL,ts_buf);
       }
      g_free(call);
     }   
     return TRUE;    
   }else 
     return FALSE;
}

void 
dump_packet(wtap_dumper* d, packet_info *p ) 
{
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
      fprintf(stderr,"%s\n",err_info);
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
    gchar   *call_id=g_strdup(sipinfo->tap_call_id);//the key for calls hash table
    gboolean free_callid = TRUE;
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
     
    call_rec_t* call = (call_rec_t*) g_hash_table_lookup(tapinfo->calls,call_id);
    if( good_invite && !(call) ) { //initialize storage,insert to db,...
       int filetype = WTAP_FILE_TYPE_SUBTYPE_PCAP;
       int encap = WTAP_ENCAP_ETHERNET;
       call = (call_rec_t*) g_new(call_rec_t,1);
       call->wd=NULL;
       call->ch1_pipe=NULL;
       call->ch2_pipe=NULL;
       call->live=FALSE;
       call->opened= (tapinfo->write_full_opened) ? FALSE : TRUE; 
       call->first_pld_sdp_frame=-1;
       nstime_copy(&(call->pkt_ts), &(pinfo->abs_ts));
       copy_address(&(call->src_ip),&(pinfo->src));

       int the_call_reqested = (tapinfo->requested_calls_only) ? 0:1; 
       /* SQL SELECT requests */ 
       PGresult* res;
       gchar* sqlrequest;
       gchar* ts_buf = my_abs_time_to_str(&pinfo->abs_ts); 

       if(tapinfo->requested_calls_only){
          gchar *from = clear_sipaddr(from_addr);
	  gchar *to = clear_sipaddr(to_addr);

          sqlrequest=g_strdup_printf("SELECT live FROM requests WHERE (( abonent_id='%s' OR  abonent_id='%s' ) AND ('%s' >= int_begin AND '%s'<= int_end ));",
                                     from,to,ts_buf,ts_buf);
	  res=PQexec(tapinfo->conn,sqlrequest);
	  if(PQresultStatus(res) != PGRES_TUPLES_OK) exiterror(PQresultErrorMessage(res));
	  if(PQntuples(res)>0){ 
	    the_call_reqested=1;
	    int nfields=PQnfields(res);
	    if(nfields!=1) exiterror("Wrong fields number in the sql reply");
            call->live = (PQgetvalue(res,0,0)[0]=='t') ? TRUE : FALSE; 
	  }
	  else the_call_reqested=0;
	  g_free(sqlrequest);
	  PQclear(res);
	  g_free(from);
	  g_free(to);
       }

       if(the_call_reqested){
         gchar* filename = g_strconcat(tapinfo->path_to_storage,"/",call_id,".pcap",NULL);
         call->wd = wtap_dump_open(filename, filetype, encap, 0, FALSE, &err);
         if(err){
            fprintf(stderr,"%s\n",wtap_strerror(err));
	    exit(1);
         }
         g_free(filename);
       }
       g_hash_table_insert(tapinfo->calls,call_id,call); 
       free_callid = FALSE;
       /* SQL INSERT (INVITE) */
       sqlrequest=g_strdup_printf("INSERT INTO cdr (calldate, clid, src, dst, disposition, pcap)  VALUES ('%s','%s', '%s', '%s', 'INVITE','%s');",
                                  ts_buf,call_id,from_addr,to_addr, (the_call_reqested) ? ("TRUE"):("FALSE") );
       res = PQexec(tapinfo->conn,sqlrequest);
       if (PQresultStatus(res) != PGRES_COMMAND_OK) exiterror(PQresultErrorMessage(res));
       PQclear(res);
       g_free(sqlrequest);
       wmem_free(NULL,ts_buf);
       if(tapinfo->debug){
         printf("INVITE SIP frame: %u; ",frame_number);
         printf("request method: %s; ",request_method);
         printf("cseq_number: %u; ",cseq_number);
         printf("call_id: %s\n",call_id);
       }
    }else if (call) nstime_copy(&(call->pkt_ts), &(pinfo->abs_ts));
    
    if(call){
     if(call->wd) dump_packet(call->wd,pinfo);

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
	    if(call->wd){
              wtap_dump_flush(call->wd);
              if(!wtap_dump_close(call->wd, &err)){
 	         fprintf(stderr,"%s\n",g_strerror(err));
	      }
	      if(call->live){
	        if(call->ch1_pipe) pclose(call->ch1_pipe);
                if(call->ch2_pipe) pclose(call->ch2_pipe);
	      }
	      if(&(call->src_ip)) free_address(&(call->src_ip));
            }
            PGresult* res;
	    gchar* sqlrequest;
	    gchar* ts_buf = my_abs_time_to_str(&pinfo->abs_ts);
	    /* SQL */
            sqlrequest=g_strdup_printf("UPDATE cdr SET disposition='CLOSED',duration=EXTRACT(SECOND FROM ( '%s'- calldate )) WHERE clid='%s';",
                                       ts_buf, sipinfo->tap_call_id);
	    res = PQexec(tapinfo->conn,sqlrequest);
	    if (PQresultStatus(res) != PGRES_COMMAND_OK) exiterror(PQresultErrorMessage(res));
	    PQclear(res);
	    g_free(sqlrequest);
	    wmem_free(NULL,ts_buf);

            g_hash_table_remove(tapinfo->calls,call_id); 
	    g_hash_table_foreach_remove(tapinfo->sdp_frames,(GHRFunc)sdp_rm_vals,call_id);
            g_hash_table_foreach_remove(tapinfo->payload_files,(GHRFunc)payload_rm_vals,call_id);

            /* info for debug */
	    if(tapinfo->debug){
              printf("BYE/CANSEL SIP frame: %u; ",frame_number);
              printf("response code: %u - %s; ",response_code,reason_phrase);
              printf("cseq_number: %u; ",cseq_number);
              printf("cseq method: %s; ",cseq_method);
              printf("call_id: %s\n",call_id);
            }
	    /*clear suspended calls by  timeout*/
	    nstime_copy(&(tapinfo->pkt_ts), &(pinfo->abs_ts));
            g_hash_table_foreach_remove(tapinfo->calls,(GHRFunc)rm_calls_by_timeout,tapinfo);
	  }else if(response_code==200 && ( strcmp(cseq_method,"INVITE")==0 )) call->opened=TRUE;
        }
      }
    }
    if(free_callid) g_free(call_id);
    g_free(request_method);
    g_free(from_addr);
    g_free(to_addr);
    g_free(reason_phrase);

    return FALSE;
}

static gboolean
rtpsave_sdp_packet(void *arg _U_, packet_info *pinfo, epan_dissect_t *edt _U_, void const *sdp_info_ptr _U_)
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
rtpsave_packet(void *arg _U_, packet_info *pinfo, epan_dissect_t *edt _U_, void const *rtp_info_ptr)
{
    sip_calls_t *tapinfo = (sip_calls_t *)arg;

    const struct _rtp_info *rtpinfo = (const struct _rtp_info *)rtp_info_ptr;
    guint32 ssrc=rtpinfo->info_sync_src;
    guint32 frame_number= pinfo->num;
    // guint16 seq_num=rtpinfo->info_seq_num;
    guint8  payload_type = rtpinfo->info_payload_type;
    guint32 setup_frame_num=rtpinfo->info_setup_frame_num;

    gchar* call_id  = (gchar*) g_hash_table_lookup(tapinfo->sdp_frames,&setup_frame_num);
    if(call_id==NULL){
       /* fprintf(stderr,"Can't find SDP/SIP data for the RTP frame:%d, SDP frame:%d\n",frame_number, setup_frame_num); Not SIP call RTP data*/
       return FALSE;
    } 

    call_rec_t* call = (call_rec_t*) g_hash_table_lookup(tapinfo->calls,call_id);
    if(!call){
       fprintf(stderr,"Can't find registered SIP call for the RTP frame:%d, SDP frame:%d\n",frame_number, setup_frame_num);
       return FALSE;
    }

    nstime_copy(&(call->pkt_ts), &(pinfo->abs_ts));
    //// save the packet to pcap file
    if(call->wd) dump_packet(call->wd,pinfo);
    else return FALSE;
    //
    //// save the packet payload to a file
    //make payload filename
    gchar* filename = g_strdup_printf("%s_%u.%u",call_id,ssrc,payload_type); //don't free here, it's key for hash table
    gboolean free_fn=TRUE;
    gchar* filepath = g_strconcat(tapinfo->path_to_storage,"/payload/",filename,NULL);
    payload_file_t* payload_f = (payload_file_t*) g_hash_table_lookup(tapinfo->payload_files,filename);

    if( !payload_f && call->opened ){
        payload_f = g_new(payload_file_t,1);
        payload_f->ph = NULL;
	nstime_copy(&(payload_f->pkt_ts), &(pinfo->abs_ts));
        payload_f->ph = fopen(filepath, "wb");
	if (payload_f->ph == NULL) 
	     exiterror(g_strconcat(g_strerror(errno)," ",filepath,"\n",NULL)); 

        if( &(call->src_ip) && cmp_address(&(call->src_ip),&(pinfo->src))==0) payload_f->caller = TRUE;
        else payload_f->caller = FALSE;

	if( call->live && payload_f->caller && tapinfo->ch1_live_cmd && !call->ch1_pipe ){
            call->ch1_pipe = popen(tapinfo->ch1_live_cmd,"w");
	    if(call->ch1_pipe == NULL) 
	      g_strconcat(g_strerror(errno)," ",tapinfo->ch1_live_cmd,"\n",NULL);
	}else if( call->live && !payload_f->caller && tapinfo->ch2_live_cmd && !call->ch2_pipe ){
            call->ch2_pipe = popen(tapinfo->ch2_live_cmd,"w");  
	    if(call->ch2_pipe == NULL)
	      g_strconcat(g_strerror(errno)," ",tapinfo->ch2_live_cmd,"\n",NULL);
	}

	payload_f->conn = tapinfo->conn;
	g_hash_table_insert(tapinfo->payload_files,filename,payload_f);
        free_fn=FALSE;
	/*SQL INSERT files*/
	PGresult* res;
	gchar* ts_buf = my_abs_time_to_str(&pinfo->abs_ts);
	gchar* sqlrequest;
	sqlrequest=g_strdup_printf( "INSERT INTO files (clid, ssrc, codec, f_opened, filename, caller)  VALUES ('%s','%u', '%u', '%s', '%s', '%s');",
                                    call_id, ssrc, payload_type, ts_buf, filename, payload_f->caller ? ("TRUE"):("FALSE") );

	res = PQexec(tapinfo->conn,sqlrequest);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) exiterror(PQresultErrorMessage(res));
	PQclear(res);
	g_free(sqlrequest);
	wmem_free(NULL,ts_buf);

    }else if(payload_f) nstime_copy(&(payload_f->pkt_ts), &(pinfo->abs_ts));

    const guint8* payload_data=rtpinfo->info_data + rtpinfo->info_payload_offset;
    guint32 payload_len=rtpinfo->info_payload_len-rtpinfo->info_padding_count;

    if(payload_f && payload_f->ph && payload_len && rtpinfo->info_data && payload_data){
      size_t nchars;
      nchars=fwrite(payload_data, sizeof(unsigned char), payload_len, payload_f->ph);
      if(nchars != payload_len) fprintf(stderr," write error %s %s\n",g_strerror(errno),filepath);
      if( call->live ){
        if( payload_f->caller && call->ch1_pipe )
	  nchars=fwrite(payload_data, sizeof(unsigned char), payload_len, call->ch1_pipe);
	  fflush(call->ch1_pipe);
	if(!payload_f->caller && call->ch2_pipe )   
          nchars=fwrite(payload_data, sizeof(unsigned char), payload_len, call->ch2_pipe);
	  fflush(call->ch2_pipe);
      }
    }
    if(free_fn) g_free(filename);
    g_free(filepath);

    return FALSE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////

static void
rtpsave_draw(void *arg _U_)
{
    sip_calls_t* tapinfo = (sip_calls_t *) arg;

    if(tapinfo->debug) printf("RTP draw (memory clearing and finish of the tap).\n");
    g_hash_table_destroy( tapinfo->sdp_frames );
    g_hash_table_foreach( tapinfo->payload_files, (GHFunc)sip_reset_hash_payload_files, NULL);
    g_hash_table_destroy( tapinfo->payload_files );
    g_hash_table_foreach( tapinfo->calls, (GHFunc)sip_reset_hash_calls, tapinfo );
    g_hash_table_destroy( tapinfo->calls );
    if (PQstatus(tapinfo->conn) == CONNECTION_OK) PQfinish(tapinfo->conn);
    g_free(tapinfo->path_to_storage);
    g_free(tapinfo->ch1_live_cmd);
    g_free(tapinfo->ch2_live_cmd);
    return; 
}

static void
rtpsave_sip_draw(void *arg _U_)
{   
    /*sip_calls_t* tapinfo = (sip_calls_t *) arg;
    if(tapinfo->debug)  printf("SIP draw (finish of the tap). \n");*/
    return; 
}

static void
rtpsave_reset(void *arg _U_)
{
    sip_calls_t *tapinfo = (sip_calls_t *) arg; 

    g_hash_table_destroy( tapinfo->sdp_frames );
    g_hash_table_foreach( tapinfo->payload_files, (GHFunc)sip_reset_hash_payload_files, NULL);
    g_hash_table_destroy( tapinfo->payload_files );
    g_hash_table_foreach( tapinfo->calls, (GHFunc)sip_reset_hash_calls,  tapinfo );
    g_hash_table_destroy( tapinfo->calls );
    if (PQstatus(tapinfo->conn) == CONNECTION_OK) PQfinish(tapinfo->conn);
    g_free(tapinfo->path_to_storage);
    g_free(tapinfo->ch1_live_cmd);
    g_free(tapinfo->ch2_live_cmd);
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
    
    sip_calls.calls=g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    sip_calls.sdp_frames=g_hash_table_new_full(g_int_hash, g_int_equal, g_free, g_free);
    sip_calls.payload_files=g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    GKeyFile *key_file;
    GError *error;

    gchar*   db_connection;
    
    key_file = g_key_file_new();
    if(!g_key_file_load_from_file(key_file, PATH_TO_CONF, G_KEY_FILE_NONE, &error))
        exiterror(error->message);
    
    sip_calls.path_to_storage = g_key_file_get_string(key_file, "config", "PATH_TO_STORAGE", &error);
    if(!sip_calls.path_to_storage) exiterror(error->message);

    sip_calls.ch1_live_cmd = g_key_file_get_string(key_file, "config", "CH1_LIVE_PIPE", &error);
    if(!sip_calls.ch1_live_cmd) exiterror(error->message);
    sip_calls.ch2_live_cmd = g_key_file_get_string(key_file, "config", "CH2_LIVE_PIPE", &error);
    if(!sip_calls.ch2_live_cmd) exiterror(error->message);

    db_connection   = g_key_file_get_string(key_file, "config", "DB_COONNECTION", &error);
    if(!db_connection) exiterror(error->message);
    if(db_connection[0]=='"') db_connection[0]=' ';
    if(db_connection[strlen(db_connection)-1]=='"') db_connection[strlen(db_connection)-1]=' ';
    
    sip_calls.requested_calls_only = g_key_file_get_boolean(key_file, "config", "REQUESTED_CALLS_ONLY", &error);
    if(!(sip_calls.requested_calls_only) && error ) exiterror(error->message);

    sip_calls.debug = g_key_file_get_boolean(key_file, "config", "DEBUG", &error);
    if( !(sip_calls.debug) && error ) exiterror(error->message);
 
    sip_calls.write_full_opened = g_key_file_get_boolean(key_file, "config", "WRITE_FULL_OPENED", &error);
    if( !(sip_calls.write_full_opened) && error ) exiterror(error->message);

    sip_calls.call_timout = g_key_file_get_double(key_file, "config", "CALL_TIMEOUT", &error);

    g_key_file_free (key_file);
    if(sip_calls.debug){
      printf("path:%s\n",sip_calls.path_to_storage);
      printf("db:%s\n",db_connection);
      printf("requ:%d\n",sip_calls.requested_calls_only);
      printf("tout:%f\n",sip_calls.call_timout);
      printf("live_pipe_ch1::%s\n",sip_calls.ch1_live_cmd);
      printf("live_pipe_ch2::%s\n",sip_calls.ch2_live_cmd);
    }

    sip_calls.conn = PQconnectdb(db_connection);
    if (PQstatus(sip_calls.conn) != CONNECTION_OK) exiterror(PQerrorMessage(sip_calls.conn));
    g_free(db_connection);
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
