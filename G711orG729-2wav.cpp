#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <string.h>

extern "C"
{
#include <bcg729/decoder.h>
#include "typedef.h"
#include "codecParameters.h"
}

using namespace std;

int32_t decodeG729(vector<int16_t> & dest, const vector<unsigned char> & src)
{
        uint8_t inputBuffer[10] = { 0 };
        int framesize = ( src.size() < 8 ) ? 2 : 10;
        uint32_t decodesize = 0;

        //create the decoder 
	bcg729DecoderChannelContextStruct *Decoder = initBcg729DecoderChannel();

        while (decodesize < src.size())
        {
                memcpy(inputBuffer, src.data() + decodesize, framesize);
                decodesize += framesize;
		
		framesize = ( src.size() - decodesize < 8 ) ? 2 : 10;

                uint8_t frameErasureFlag1 = 0;
                if ((uint8_t)inputBuffer[0] == 0) //frame has been erased
                {
                        frameErasureFlag1 = 1;
                }

                int16_t tempoutpuBuffer[L_FRAME] = { 0 };
                bcg729Decoder(Decoder, inputBuffer, frameErasureFlag1, tempoutpuBuffer);
                dest.insert(dest.end(), tempoutpuBuffer, tempoutpuBuffer + L_FRAME);

        }
        //release decoder
        closeBcg729DecoderChannel(Decoder);
        return dest.size();
}

#pragma pack(push, 1)
struct WAVHEADER
{
    uint8_t chunkId[4]={0x52,0x49,0x46,0x46};     //"RIFF"
    int32_t chunkSize;                            // length 36 + size(pcm payload)
    uint8_t format[4]={0x57,0x41,0x56,0x45};      //"WAVE"
    //
    uint8_t subchunk1Id[8]={0x66,0x6d,0x74,0x20,0x12,0,0,0}; //"fmt "
    //int32_t subchunk1Size=0x12;  //0x12, moved to subchunk1Id
    int16_t audioFormat;    //7 - u-low(0), 6 - a-low(8),  
    int16_t numChannels;    //1 - mono, 2 -stereo
    int32_t sampleRate;     // 8000Hz, 16000Hz, 44100Hz, ...
    int32_t byteRate;       // sampleRate * numChannels * bitsPerSample/8
    int16_t blockAlign;     //numChannels * bitsPerSample/8
    int16_t bitsPerSample;  // 8bit, 16bit, ...
    //looks like an undocumented RIFF extentions
    uint8_t pad1[10]={0,0,0x66,0x61,0x63,0x74,4,0,0,0}; //"\0\0fact\0\4\0\0\0"
    int32_t pad2;            
    //
    uint8_t subchunk2Id[4]={0x64,0x61,0x74,0x61}; //"data"
    int32_t subchunk2Size; //datasize, numSamples * numChannels * bitsPerSample/8, part2

} wavheader;
#pragma pack(pop)

int main( int argc, char** argv ) {
   int16_t numChannels=1; 
   int32_t sampleRate=8000;
   int16_t bitsPerSample=8;
   int16_t audioFormat=6;
   vector<int16_t> pRawData;
   unordered_map<string,int16_t> codecs;
   codecs["8"]=6; // PCMA a-low(8) G711a encoded by 6 in WAV
   codecs["0"]=7; // PCMA mu-low(0) G711u encoded by  in WAV
   codecs["18"]=18; // just trick for G729

   if (argc < 2) { // We expect at least 2 arguments: the program name, the raw file 
        cerr << "Usage: " << argv[0] << " <raw-file> [6 (audio-format, default corr. A-low a711 8] [<num-channels> (default 1)] [<sampleRate> (def 8000))] [8 (bps)]" << endl;
	cerr << "       The parameters are positional, so specify all previous before one needed."<< endl;
        return (-1);
    }

   if (argc > 2){ 
     auto search = codecs.find(argv[2]);
     if(search != codecs.end()) audioFormat=codecs[argv[2]];
     else{
        cerr << "Usage: " << argv[0] << " <raw-file> [6 (audio-format, default corr. A-low a711 8] [<num-channels> (default 1)] [<sampleRate> (def 8000))] [8 (bps)]" << endl;
	cerr << "       The parameters are positional, so specify all previous before one needed."<< endl;
        return (-1);
     } 
   }
   if (argc > 3) numChannels=stoi(argv[3]);
   if (argc > 4) sampleRate=stoi(argv[4]);
   if (argc > 5) bitsPerSample=stoi(argv[5]);

   ifstream pcm_input(argv[1], ifstream::binary);
   ofstream wav_output(string(argv[1])+".wav",ofstream::binary);

   if(!pcm_input.is_open()){
   	cout << "Unable to open input file"<<endl;
	return (-1);
   }
   if(!wav_output.is_open()){
   	cout << "Unable to open output file"<<endl;
	return (-1);
   }

   pcm_input.seekg(0, pcm_input.end);
   int length = pcm_input.tellg();
   pcm_input.seekg(0, pcm_input.beg);

   char * buffer = new char [length];

   pcm_input.read(buffer,length);
   int32_t bytes_readed = pcm_input.gcount();
   pcm_input.close();
  
   if(audioFormat==18){//g729, convert the payload to pcm, then save pcm  to wav
       std::vector<unsigned char> pcmBuffer;
       pcmBuffer.resize(bytes_readed);
       memcpy((char *) pcmBuffer.data(),buffer,bytes_readed);
       decodeG729(pRawData, pcmBuffer);
       audioFormat=1;
       bitsPerSample=16; 
   }
   //
   //The following block works right on little endian processors
   if(audioFormat==1){ //pcm from g729, get size for wav from the pcm vector
     wavheader.chunkSize=50+pRawData.size()*2; //36was
     wavheader.pad2=pRawData.size()*2;
     wavheader.subchunk2Size=pRawData.size()*2;
   }else{ //g711 , get size for wav from the original payload
     wavheader.chunkSize=50+bytes_readed; //36was
     wavheader.pad2=bytes_readed;
     wavheader.subchunk2Size=bytes_readed;
   }
   wavheader.audioFormat=audioFormat;
   wavheader.numChannels=numChannels; 
   wavheader.sampleRate=sampleRate; 
   wavheader.byteRate=sampleRate * numChannels * bitsPerSample/8;
   wavheader.blockAlign=numChannels*bitsPerSample/8;
   wavheader.bitsPerSample=bitsPerSample;
   //
   wav_output.write((char *) &wavheader,sizeof(wavheader));
   
   if(audioFormat==1) //pcm from g729, save the pcm  to wav
      wav_output.write((char *)pRawData.data(),pRawData.size()*2);    
   else //g711a or g711mu, just save the payload to wav 
      wav_output.write(buffer,bytes_readed);

   cout << "Bytes readed:" << bytes_readed << ", and written: "<< wav_output.tellp() << endl;
   wav_output.close();
   delete [] buffer;

   return 0;
}


