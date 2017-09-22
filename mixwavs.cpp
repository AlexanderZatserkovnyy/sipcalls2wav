#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <stdlib.h>
#include <libpq-fe.h>

#define DB_COONNECTION "host=localhost dbname=voiplog user=dbworker password='vFcnbh_+'"

using namespace std;

string wav_dir = "/data/pcaps1/wav/";
string sox = "/usr/bin/sox ";

const char* usage = " <callid> <output-wav-file>\n"
                    "e.g. 12013223@200.57.7.195 two-voices.wav\n";

PGconn* conn;

typedef struct _wav_file_info {
  string filename;
  long double ts_opened;
  long double ts_closed;
  uint32_t ssrc;
  uint32_t samples;
} wav_file_info;

void exiterror(char *mess)
{
  cerr << string(mess) << endl;
  exit(1);
}

bool cmp(wav_file_info a, wav_file_info b) { return (a.ts_opened<b.ts_opened); }

int main( int argc, char** argv ) {
  
  if (argc!=3) {  
      cerr << "Usage: " << argv[0] << usage;
      return (EXIT_FAILURE);
  }

  string call_id(argv[1]);
  string res_wav(argv[2]);

  //cout << call_id << endl;
  //cout << res_wav << endl;

  conn = PQconnectdb(DB_COONNECTION);
  if (PQstatus(conn) != CONNECTION_OK) exiterror(PQerrorMessage(conn));
  
  string sqlrequest = "SELECT filename,extract(epoch from f_opened),extract(epoch from f_closed), samples, ssrc FROM files WHERE clid='"+
                     call_id + "' AND samples!=0 ORDER BY f_opened;";
  PGresult* res = PQexec(conn,sqlrequest.c_str());
  if (PQresultStatus(res) != PGRES_TUPLES_OK) exiterror(PQresultErrorMessage(res));
  int ntuples=PQntuples(res);
  int nfields=PQnfields(res);
  if(ntuples<2) exiterror("Wav sources not ready, following SQL table 'files'.");
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
  std::sort (wavs.begin(), wavs.end(), cmp);

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
  if(ch2.size()==0) exiterror("The channel 2 empty.");

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
  }else{
    tmp = (wav_file_info) *(ch2.begin());
    ch2_fn= wav_dir + tmp.filename + ".wav";
  }

  cout << fixed << "Ch1, fn:" << ch1_fn << " begin:" << ch1_b  << " end:"   << ch1_e << " samples=" << ch1_samples << endl;
  cout << fixed << "Ch2, fn:" << ch2_fn << " begin:" << ch2_b  << " end:"   << ch2_e << " samples=" << ch2_samples << endl;
  cout << fixed << "pad_b:"  << pad_b << " pad_e:" << pad_e << endl; 

  //make stereo
  string ch1_cmd="\"|sox "+ch1_fn+" -p pad " +to_string(ch1_pad_b)+"s "+to_string(ch1_pad_e)+"s\""; 
  string ch2_cmd="\"|sox "+ch2_fn+" -p pad " +to_string(ch2_pad_b)+"s "+to_string(ch2_pad_e)+"s\""; 
  args= sox+" -M "+ch1_cmd+" "+ch2_cmd+" "+res_wav;
  system(args.c_str());
 
  if (PQstatus(conn) == CONNECTION_OK) PQfinish(conn);
  return 0;
}


