#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>

#include <string.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <libpq-fe.h>


using namespace std;

const char* usage = "<path-to-payload-dir> <path-to-wav-dir>\n";

typedef struct _wav_file_info {
  string filename;
  long double ts_opened;
  long double ts_closed;
  uint32_t ssrc;
  uint32_t samples;
} wav_file_info;

bool cmp(wav_file_info a, wav_file_info b) { return (a.ts_opened<b.ts_opened); }

#define PATH_TO_CONF "/data/conf/tap-rtpsave.conf"
/* #define DB_COONNECTION "host=localhost dbname=voiplog user=dbworker password='vFcnbh_+'" */

PGconn* conn;

void exiterror(string mess)
{
  cerr << mess;
  exit(1);
}

map<string,string> LoadConfig(string filename)
{
    ifstream in(filename);
    map<string,string> res;
    while(in)
    {
      string ln;
      getline(in, ln);
      string::size_type p_d=ln.find_first_of('=');
      if( p_d != string::npos ){
         string raw_key=ln.substr(0,p_d);
         string::size_type pk_b = raw_key.find_first_not_of(" \t");
         if( pk_b != string::npos ){
            string::size_type pk_e = raw_key.find_last_not_of(" \t");
            if( pk_e != string::npos ){
               string raw_value =ln.substr(p_d+1,string::npos);
               string::size_type pv_b = raw_value.find_first_not_of(" \t");
               if( pv_b != string::npos ){
                  string::size_type pv_e = raw_value.find_last_not_of(" \t");
                  if( pv_e != string::npos ){
                     res[raw_key.substr(pk_b,pk_e-pk_b+1)] = raw_value.substr(pv_b,pv_e-pv_b+1);
                     string::size_type pos1 = raw_value.find_first_of("\"");
                     string::size_type pos2 = raw_value.find_last_of("\"");
                     if(pos1 != string::npos && pos2 != string::npos && pos2 > pos1) 
                       res[raw_key.substr(pk_b,pk_e-pk_b+1)] = raw_value.substr(pos1+1,pos2-pos1-1);
                  }
               }
            }
         }
      }
    }
    in.close();
    return res;
}


int mixwavs( string& wav_dir, string& call_id, bool debug_output ){

  string sox = "/usr/bin/sox ";
  string sqlrequest = "SELECT filename,extract(epoch from f_opened),extract(epoch from f_closed), samples, ssrc FROM files WHERE clid='"+
                     call_id + "' AND samples!=0 ORDER BY f_opened;";
  PGresult* res = PQexec(conn,sqlrequest.c_str());

  if (PQresultStatus(res) != PGRES_TUPLES_OK) exiterror(PQresultErrorMessage(res));
  int ntuples=PQntuples(res);
  int nfields=PQnfields(res);
  if(ntuples<2) return 0;
  if(nfields!=5) exiterror("Wrong number of fields in the select result from table 'files'.");

  wav_file_info tmp;
  vector<wav_file_info> wavs,ch1,ch2;
  for(int i = 0; i < ntuples; i++){
     tmp.filename=string(PQgetvalue(res, i, 0));
     tmp.ts_opened=stold(PQgetvalue(res, i, 1));
     tmp.ts_closed=stold(PQgetvalue(res, i, 2));
     tmp.samples=stoul(PQgetvalue(res, i, 3));
     tmp.ssrc=stoul(PQgetvalue(res, i, 4));
     wavs.push_back(tmp);
     //cout<< tmp.filename << " " << tmp.ts_closed - tmp.ts_opened << " " << tmp.samples << endl;
  }
  PQclear(res);

  if(wavs.size()<2) return 0; 
  std::sort (wavs.begin(), wavs.end(), cmp); //Don't needed. It must be ordered already.

  long double ch1_b=0, ch1_e=0, ch2_b=0, ch2_e=0;
  uint32_t    ch1_samples=0, ch2_samples=0;
  uint32_t    ch1_ssrc=0, ch2_ssrc=0;
  string      ch1_fn, ch2_fn;

  auto it=wavs.begin();
  ch1.push_back(*it);
  tmp = (wav_file_info) *it;
  ch1_b = tmp.ts_opened;
  ch1_e = tmp.ts_closed;
  ch1_samples = tmp.samples;
  ch1_ssrc=tmp.ssrc;
  it++;
  for(; it!=wavs.end(); ++it ){
     tmp= (wav_file_info) *it;
     if(tmp.ssrc==ch1_ssrc){
        ch1.push_back(*it);
        ch1_e = tmp.ts_closed;
        ch1_samples += tmp.samples;
     }else if(tmp.ssrc==ch2_ssrc){
        ch2.push_back(*it);
        if(ch2_b==0) ch2_b=tmp.ts_opened;
        ch2_e = tmp.ts_closed;
        ch2_samples += tmp.samples;
     }else if( tmp.ts_opened>ch1_e ){
        ch1.push_back(*it);
        ch1_e = tmp.ts_closed;
        ch1_samples += tmp.samples;
        ch1_ssrc=tmp.ssrc;
     }else {
        ch2.push_back(*it);
        if(ch2_b==0) ch2_b=tmp.ts_opened;
        ch2_e = tmp.ts_closed;
        ch2_samples += tmp.samples;
        ch2_ssrc=tmp.ssrc;
     }
  }

  if(ch1.size()==0) exiterror("The channel 1 empty.");

  int32_t pad_b=0, pad_e=0; //if pad<0 it must be added to ch1
  int32_t d_s=ch1_samples-ch2_samples;
  long double diff_b=ch2_b-ch1_b; //
  long double diff_e=ch1_e-ch2_e;

  if(diff_e+diff_b){
     pad_b = (int) d_s*(diff_b/(diff_e+diff_b));
     pad_e = (int) d_s*(diff_e/(diff_e+diff_b));
  }

  uint32_t ch1_pad_b= (pad_b>0) ? 0 : (-pad_b);
  uint32_t ch2_pad_b= (pad_b>0) ? pad_b : 0;
  uint32_t ch1_pad_e= (pad_e>0) ? 0 : (-pad_e);
  uint32_t ch2_pad_e= (pad_e>0) ? pad_e : 0;
  if(ch1_pad_b>0){
         ch1_pad_b=(d_s>0) ? 0 : (-d_s);
	 ch1_pad_e=0;
	 ch2_pad_b=0; 
	 ch2_pad_e=(d_s>0) ? d_s : 0;
  } 

  //concatenate files in a channel if needed
  string args;
  if(ch1.size()>1){
    args=" ";
    for( it=ch1.begin(); it!=ch1.end(); ++it ){
       tmp = (wav_file_info) *it;
       args += wav_dir + tmp.filename + ".wav ";
    }
    args = sox+ args + wav_dir + call_id + ".ch1.wav";
    system(args.c_str());
    ch1_fn=wav_dir + call_id + ".ch1.wav";
  }else{
    tmp = (wav_file_info) *(ch1.begin());
    ch1_fn= wav_dir + tmp.filename + ".wav";
  }
   //concatenate files in a channel if needed
  if(ch2.size()>1){
    string args(" ");
    for( it=ch2.begin(); it!=ch2.end(); ++it ){
       tmp = (wav_file_info) *it;
       args += wav_dir + tmp.filename + ".wav ";
    }
    args = sox+ args + wav_dir + call_id + ".ch2.wav";
    system(args.c_str());
    ch2_fn=wav_dir+call_id + ".ch2.wav";
  }else if(ch2.size()==1){
    tmp = (wav_file_info) *(ch2.begin());
    ch2_fn= wav_dir + tmp.filename + ".wav";
  }

  if(ch2.size()>0){  //make stereo
    string ch1_cmd="\"|sox "+ch1_fn+" -p pad " +to_string(ch1_pad_b)+"s "+to_string(ch1_pad_e)+"s\"";
    string ch2_cmd="\"|sox "+ch2_fn+" -p pad " +to_string(ch2_pad_b)+"s "+to_string(ch2_pad_e)+"s\"";
    args= sox+" -M "+ch1_cmd+" "+ch2_cmd+" "+wav_dir+call_id+".wav";
    if(debug_output) cout << "CallID:"<< call_id << endl;
    system(args.c_str());
  } 

  return 0;
}

static void handle_events(int fd, int wd, string &wav_path, bool debug_output ) {
  char buf[4096]
       __attribute__ ((aligned(__alignof__(struct inotify_event))));

  const struct inotify_event *event;
  ssize_t len;
  char *ptr;

  for (;;) {
    len = read(fd, buf, sizeof(buf));
    if (len == -1 && errno != EAGAIN) {
       perror("read");
       exit(EXIT_FAILURE);
    }
    if (len <= 0) break;
    for (ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
      event = (const struct inotify_event *) ptr;
      if (event->wd == wd ){
            string filename(event->name);
	    string::size_type pos = filename.find_first_of('_'); // it's a part of a single channel sound
            if(pos!=string::npos){
	       string call_id = filename.substr(0,pos); 
	       mixwavs(wav_path, call_id, debug_output);
	    }
      }
    }
  }
}

int main( int argc, char** argv ) {
  string wavpath; 

  if (argc > 1) wavpath=string(argv[1]);
  
  map<string,string> conf=LoadConfig(string(PATH_TO_CONF));

  bool debug_output = 0;
  auto it=conf.find("DEBUG");
  if(it!=conf.end()) debug_output=stoi(it->second);

  it=conf.find("DB_COONNECTION");
  if(it==conf.end()) exiterror("Can't find DB_COONNECTION configuration in the conf file "); 
  string db_connection=it->second;
  if(debug_output) cout << "DB:" << db_connection << endl;

  if(argc < 2){  // command line wavepath has priority over conf file wavepath
     it=conf.find("PATH_TO_STORAGE");
     if(it==conf.end()) exiterror("Can't find PATH_TO_STORAGE configuration in the conf file ");
     wavpath= it->second + "/wav/";
  } 

  if(wavpath.at(wavpath.length()-1)!='/') wavpath +='/';

  int fd, poll_num, wd;
  struct pollfd fds[1];
  nfds_t nfds;
  
  fd = inotify_init1(IN_NONBLOCK);
  if (fd == -1) {
      perror("inotify_init1");
      return (EXIT_FAILURE);
  }
  
  wd = inotify_add_watch(fd, wavpath.c_str(), IN_CLOSE_WRITE);
  if(wd == -1) {
      cerr << "Impossible to observe:" << wavpath << endl;
      perror("inotify_add_watch");
      return (EXIT_FAILURE);
  } 

  nfds = 1;
  fds[0].fd = fd;
  fds[0].events = POLLIN;


  conn = PQconnectdb(db_connection.c_str());

  if (PQstatus(conn) != CONNECTION_OK) exiterror(PQerrorMessage(conn));

  cout << "Wait events."<< endl;
  while(1) {
      poll_num = poll(fds, nfds, -1);
      if (poll_num == -1) {
           if (errno == EINTR)
               continue;
           perror("poll");
           exit(EXIT_FAILURE);
      }
      if (poll_num > 0) {
           if (fds[0].revents & POLLIN) handle_events(fd, wd, wavpath, debug_output);
      }
  }

  if (PQstatus(conn) == CONNECTION_OK) PQfinish(conn);
  return 0;
}


