#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

int main(int argc, char *argv[])
{
	HANDLE handle;
	char packet[65535];
	WINDIVERT_ADDRESS addr;
	UINT packet_len;
	int i, port;
	PWINDIVERT_IPHDR ip_header;
	WINDIVERT_UDPHDR * udp_header;
	UINT payload_len;
	UINT origin_ip, change_ip;

	if (argc < 4)
	{
		printf("FileName SrcIP DstIp port");
		return 1;
	}


	WinDivertHelperParseIPv4Address(argv[1], &origin_ip);
	WinDivertHelperParseIPv4Address(argv[2], &change_ip);
	//printf("변환전: %x\n", change_ip);

	port = atoi(argv[3]);

	handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);

	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("WinDivertOpen Error!!!\n");
		return 1;
	}

	while (true)
	{

		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			printf("WinDivertRecv Error!!\n");
			break;
		}


		WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, NULL, &udp_header, NULL, &payload_len);


		if (ip_header != NULL)
		{
			if (ip_header->DstAddr == htonl(origin_ip))
			{
				if (udp_header->DstPort == ntohs(port))
				{
					for (i = 0; i < packet_len; i++)
						printf("%02x ", packet[i]);

					UINT change = ntohl(change_ip);

					printf("\n변환: %x\n", change);

					memcpy(packet + 16, &change, sizeof(UINT));

					printf("\n\n\n\n\n\n");

					for (i = 0; i < packet_len; i++)
						printf("%02x ", packet[i]);

					if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
					{
						printf("WinDivertSend Error!!\n");
						break;
					}
					else
						printf("보냄\n");
				}
			}
		}
	}

}




