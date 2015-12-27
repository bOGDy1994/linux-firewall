//user space code using libnetfilter_queue

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>


#define MAX_RULES 255
int noRules = 0;

struct rule
{
  char ip[INET_ADDRSTRLEN];
  int protocol;
  int port;//-1 means we do not care about the port
  int action;//0 for denial, 1 for allowance
};

struct nfq_handle *h;
struct nfq_q_handle *qh;
int fd;
char buf[4096] __attribute__ ((aligned));
int rv;
struct rule Rules[MAX_RULES];

void eldots(char *buffin, char*buffout)
{
  int i = 0;
  int len = strlen(buffin);
  int n = 0;
  while(i < len)
    {
      if(buffin[i] != '.')
	{
	  buffout[n]=buffin[i];
	  n++;
	}
      i++;
    }
  buffout[n] = '\0';
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
         int id = 0;
         struct nfqnl_msg_packet_hdr *ph;
         struct nfqnl_msg_packet_hw *hwph;
         u_int32_t mark,ifi; 
         int ret;
         unsigned char *data;
 
         ph = nfq_get_msg_packet_hdr(tb);
         if (ph)
	 {
                 id = ntohl(ph->packet_id);
                 printf("hw_protocol=0x%04x hook=%u id=%u ",
                         ntohs(ph->hw_protocol), ph->hook, id);
         }
         hwph = nfq_get_packet_hw(tb);
         if (hwph)
	 {
                 int i, hlen = ntohs(hwph->hw_addrlen);
 
                 printf("hw_src_addr=");
                 for (i = 0; i < hlen-1; i++)
                         printf("%02x:", hwph->hw_addr[i]);
                 printf("%02x ", hwph->hw_addr[hlen-1]);
         }
         mark = nfq_get_nfmark(tb);
         if (mark)
                 printf("mark=%u ", mark);
 
         ifi = nfq_get_indev(tb);
         if (ifi)
                 printf("indev=%u ", ifi);
 
         ifi = nfq_get_outdev(tb);
         if (ifi)
                 printf("outdev=%u ", ifi);
         ifi = nfq_get_physindev(tb);
         if (ifi)
                 printf("physindev=%u ", ifi);
         ifi = nfq_get_physoutdev(tb);
         if (ifi)
                 printf("physoutdev=%u ", ifi);
 
         ret = nfq_get_payload(tb, &data);
         if (ret >= 0)
                 printf("payload_len=%d ", ret);
 
         fputc('\n', stdout);
 
        return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
  FILE *f;
  int foundPosition;
  struct iphdr *ipHeader;
  struct tcphdr *tcpHeader;
  struct udphdr *udpHeader;
  u_int32_t id = print_pkt(nfa);
  int payload_len;
  unsigned char *payloadData;
  unsigned char *sourceIP;
  payload_len = nfq_get_payload(nfa, &payloadData);
  ipHeader = (struct iphdr *)payloadData;
  int sadd = ipHeader->saddr;
  sourceIP = (char *)malloc(sizeof(char) * INET_ADDRSTRLEN);
  inet_ntop(AF_INET, (void *)&sadd,sourceIP, INET_ADDRSTRLEN);
  printf("Source ip address : %s - Source ip checksum : %d\n", sourceIP, ipHeader->check);
  if (ipHeader->protocol == IPPROTO_TCP)
  {
        tcpHeader = (struct tcphdr *)(payloadData + (ipHeader->ihl<<2));
	printf("Port is : %d\n", tcpHeader->dest);
  }
  //we build the rule based on the current packet
  struct rule currentRule;
  eldots(sourceIP, currentRule.ip);
  currentRule.protocol = ipHeader->protocol;
  currentRule.port = tcpHeader->dest;
  currentRule.action = 1;
  int i = 0;
  int isFound = 0;
  while((i<noRules)&&(!isFound))
    {
      if(strcmp(currentRule.ip, Rules[i].ip)==0)
	if((Rules[i].port!=-1)&&(currentRule.port!=-1))
	  {
	    if(Rules[i].port==currentRule.port)
	      if(Rules[i].protocol == currentRule.protocol)
		//if(Rules[i].action == currentRule.action)
		isFound = 1;

	  }
	else
	  {
	    if(Rules[i].protocol == currentRule.protocol)
	      isFound = 1;
	  }
      if(!isFound)
	i++;
    }
  foundPosition = i;
  if(!isFound)
    {
      strcpy(Rules[noRules].ip, currentRule.ip);
      printf("NEW RULE IP : %s\n", Rules[noRules].ip);
      Rules[noRules].protocol = currentRule.protocol;
      Rules[noRules].port = currentRule.port;
      Rules[noRules].action = 1;//suppose we are in permissive mode
      noRules++;
    }
  f = fopen("./bin/verify.in","w");
  if(f == NULL)
    {
      printf("Cannot create input file for Prover9!\n");
      exit(-1);
    }
  fprintf(f, "set(quiet).\n");
  fprintf(f, "clear(print_proofs).\n");
  fprintf(f, "formulas(sos).\n");
  for(i = 0; i<noRules; i++)
    {
      if(Rules[i].port != -1)
	fprintf(f," rule3(%s, %d, %d) = %d.\n", Rules[i].ip, Rules[i].protocol, Rules[i].port, Rules[i].action);
      else
	fprintf(f," rule2(%s, %d) = %d.\n", Rules[i].ip, Rules[i].protocol, Rules[i].action);      
    }
  /*if(!isFound)
    {
      if(currentRule.port != -1)
	fprintf(f," rule3(%s, %d, %d) = %d.", currentRule.ip, currentRule.protocol, currentRule.port, 1);
      else
	fprintf(f," rule2(%s, %d) = %d.", currentRule.ip, currentRule.protocol, 1);
	}*/
  //fprintf(f,"\n");
  fprintf(f,"end_of_list.\n\n");
  fprintf(f,"formulas(goals).\n");
  if((currentRule.port != -1)&&(!isFound))
    fprintf(f, " rule3(%s, %d, %d) = %d.\n", currentRule.ip, currentRule.protocol, currentRule.port, currentRule.action);
  else
    if(isFound)
      {
	if(Rules[foundPosition].port != -1)
	fprintf(f," rule3(%s, %d, %d) = %d.\n", Rules[foundPosition].ip, Rules[foundPosition].protocol, Rules[foundPosition].port, currentRule.action);
      else
	fprintf(f," rule2(%s, %d) = %d.\n", Rules[foundPosition].ip, Rules[foundPosition].protocol, currentRule.action);
      }
  else
    fprintf(f, " rule2(%s, %d) = %d.\n", currentRule.ip, currentRule.protocol, currentRule.action);
  fprintf(f, "end_of_list.");
  fclose(f);
  int rv = system("./bin/prover9 -f ./bin/verify.in | grep THEOREM > ./bin/ex.out");
  if((rv!=0) &&(rv!=256))
    {
      perror("Error in reading prover9! Make sure this is in the bin subfolder!\n");
      exit(-1);
    }
  struct stat st;
  stat("./bin/ex.out", &st);
  printf("Ex.out size : %d", st.st_size);
  if(st.st_size==0)
    {
      printf("\n DROPPING THE PACKAGE...\n");
      return nfq_set_verdict(qh, id, NF_DROP, payload_len, payloadData);
    }
  else
    {
      printf("\n ACCEPTING THE PACKAGE...\n");
      return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, payloadData);
    }
	
}

int main(int argc, char *argv[])
{
  noRules = 1;
  FILE *f;
  f = fopen("rules.in", "r");
  
  if(f==NULL)
    {
      printf("Cannot open rules.in!\n");
      exit(1);
    }
  fscanf(f, "%s %d %d %d", &Rules[0].ip, &Rules[0].protocol, &Rules[0].port, &Rules[0].action);
  eldots(Rules[0].ip, Rules[0].ip);
  fprintf(stdout, "%s %d %d %d \n", Rules[0].ip, Rules[0].protocol, Rules[0].port, Rules[0].action);
  fclose(f);
  printf("Opening library handle...\n");
  h = nfq_open();
  if(!h)
    {
      fprintf(stderr, "error at nfq_open");
      exit(1);
    }
  printf("Unbinding existing nf_queue handler for AF_INET(if any)...\n");
  if(nfq_unbind_pf(h, AF_INET)<0)
    {
      fprintf(stderr, "Error during nfq_unbind_pf()\n");
      exit(1);
    }
  printf("Binding nfnetlink_queue as nf_queue handler for AF_INET...\n");
  if(nfq_bind_pf(h, AF_INET)<0)
    {
      fprintf(stderr, "Error during nfq_bind_pf()\n");
      exit(1);
    }
  printf("Binding this socket to queue 0...\n");
  qh = nfq_create_queue(h,0,&cb,NULL);
  if(!qh)
    {
      fprintf(stderr, "error during nfq_create_queue()\n");
      exit(1);
    }
  printf("Setting copy packet mode...\n");
  if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
      fprintf(stderr, "error during nfq_set_mode()\n");
    }
  fd = nfq_fd(h);
  while(1)
    {
      while((rv = recv(fd, buf, sizeof(buf), 0)) && rv>0)
	{
	  printf("pkt_received...\n");
	  nfq_handle_packet(h, buf, rv);
	}
    }
  printf("Unbinding from queue...\n");
  nfq_destroy_queue(qh);
  printf("Closing library handle...\n");
  nfq_close(h);
  return 0;
}
