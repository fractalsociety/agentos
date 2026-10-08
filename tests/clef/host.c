#define _POSIX_C_SOURCE 200809L
#include <platform/clef.h>
#include <tests/fixtures/clef-resource-choice.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
static struct timespec start;
static void progress(void *ctx,const char *stage,unsigned layer)
{
    (void)ctx;struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);
    fprintf(stderr,"Clef %s %u at %.1fs\n",stage,layer,
        now.tv_sec-start.tv_sec+(now.tv_nsec-start.tv_nsec)*1e-9);
}
int main(int argc,char **argv)
{
    if(argc!=2){fprintf(stderr,"usage: %s model.gguf\n",argv[0]);return 2;}
    int fd=open(argv[1],O_RDONLY);struct stat st;
    if(fd<0 || fstat(fd,&st) || st.st_size!=CLEF_MODEL_BYTES){perror("model");return 1;}
    void *data=mmap(0,st.st_size,PROT_READ,MAP_PRIVATE,fd,0);close(fd);
    if(data==MAP_FAILED){perror("mmap");return 1;}
    void *arena=aligned_alloc(16,CLEF_ARENA_BYTES);
    if(!arena){perror("arena");return 1;}
    clef_result result={0};
    clock_gettime(CLOCK_MONOTONIC,&start);
    uint32_t error=clef_rust_run(data,st.st_size,&clef_resource_input,arena,CLEF_ARENA_BYTES,&result,progress,0);
    if(error){fprintf(stderr,"FAIL: Rust error %u\n",error);return 1;}
    int failed=result.choice!=0;
    for(unsigned i=0;i<2;++i) {
        printf("option %u logit %.9g probability %.9g reference %.9g\n",i,result.logits[i],result.probabilities[i],clef_reference_probabilities[i]);
        if(fabsf(result.probabilities[i]-clef_reference_probabilities[i])>0.02f)failed=1;
    }
    puts(failed?"CLEF_HOST_CHECK_FAIL":"CLEF_HOST_CHECK_PASS");
    free(arena);munmap(data,st.st_size);return failed;
}
