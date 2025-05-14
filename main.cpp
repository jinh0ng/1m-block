
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <set>
#include <string>
#include <time.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

// char *host;
std::set<std::string> sites;
u_int32_t verdict = NF_ACCEPT; // default verdict

void usage()
{
    printf("syntax : 1m-block <site list file>\n");
    printf("sample : 1m-block top-1m.txt\n");
}

/* returns packet id */
static uint32_t print_pkt(struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    uint32_t mark, ifi, uid, gid;
    int ret;
    unsigned char *data, *secdata;

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
        for (i = 0; i < hlen - 1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen - 1]);
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

    // if (nfq_get_uid(tb, &uid))
    //     printf("uid=%u ", uid);

    // if (nfq_get_gid(tb, &gid))
    //     printf("gid=%u ", gid);

    // ret = nfq_get_secctx(tb, &secdata);

    // if (ret > 0)
    //     printf("secctx=\"%.*s\" ", ret, secdata);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
    {
        u_int32_t iphdr_len = data[0] & 0x0f;
        iphdr_len *= 4;

        u_int32_t tcphdr_len = data[iphdr_len + 12] & 0xf0;
        tcphdr_len >>= 4;
        tcphdr_len *= 4;

        u_int32_t http_len = ret - iphdr_len - tcphdr_len;
        unsigned char *http_ptr = data + iphdr_len + tcphdr_len;

        if (http_len > 0)
        {
            char *host_ptr = strstr((char *)http_ptr, "Host: ");
            if (host_ptr)
            {
                host_ptr += 6; // "Host: " skip

                // CR/LF 전까지 탐색
                char *end = host_ptr;
                while (*end && *end != '\r' && *end != '\n')
                    ++end;
                *end = '\0';

                // 파싱된 호스트명으로만 std::string 생성
                std::string hostname(host_ptr);
                printf("parsed hostname: %s\n", hostname.c_str());

                if (!hostname.empty() && sites.find(hostname) != sites.end())
                {
                    verdict = NF_DROP;
                    printf("BLOCKED (%s)\n", hostname.c_str());
                }
                else
                {
                    verdict = NF_ACCEPT;
                    printf("ACCEPTED (%s)\n", hostname.c_str());
                }
            }
            else
            {
                // Host 헤더 자체가 없으면 기본 허용
                verdict = NF_ACCEPT;
            }
        }
    }
    fputc('\n', stdout);

    return id;
}

// NFQUEUE에서 받은 패킷을 처리리
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    uint32_t id = print_pkt(nfa);
    printf("entering callback\n");
    int ret = nfq_set_verdict(qh, id, verdict, 0, NULL);
    verdict = NF_ACCEPT; // 다음 패킷 default값 복원
    // return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    return ret;
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    uint32_t queue = 0;
    char buf[4096] __attribute__((aligned));

    if (argc != 2)
    {
        usage();
        exit(1);
    }

    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("File open error\n");
        exit(1);
    }

    char line[256];
    memset(line, 0, sizeof(line));

    time_t start, end;
    time(&start);

    // 3) 한 줄씩 읽어 와서 콤마 뒤 도메인만 추출해 삽입
    while (fgets(line, sizeof(line), fp))
    {
        // '1,google.com\r\n' → comma 가리키게
        char *comma = strchr(line, ',');
        if (!comma)
            continue;
        char *domain = comma + 1;
        // 끝 개행 제거
        domain[strcspn(domain, "\r\n")] = '\0';
        sites.insert(std::string(domain));
    }
    time(&end);
    printf("Time taken to read file: %lf \n", difftime(end, start));
    fclose(fp);

    ///////////////////////////////////////////////

    printf("opening library handle\n");
    h = nfq_open();
    if (!h)
    {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '%d'\n", queue);
    qh = nfq_create_queue(h, queue, &cb, NULL);
    if (!qh)
    {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    // printf("setting flags to request UID and GID\n");
    // if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID))
    // {
    //     fprintf(stderr, "This kernel version does not allow to "
    //                     "retrieve process UID/GID.\n");
    // }

    // printf("setting flags to request security context\n");
    // if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX))
    // {
    //     fprintf(stderr, "This kernel version does not allow to "
    //                     "retrieve security context.\n");
    // }

    // printf("Waiting for packets...\n");

    fd = nfq_fd(h);

    for (;;)
    {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
        {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS)
        {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    sites.clear();
    exit(0);
}
