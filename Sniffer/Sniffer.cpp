// Sniffer.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "iphdr.h"

std::vector< std::string > getInterfaces()
{
	std::vector< std::string > lst;
	try
	{
		char     hostname[MAX_PATH];
		HOSTENT *hostaddr;
		int      adapter_idx = 0;
		struct sockaddr_in   address;

		int ret = gethostname( hostname, sizeof( hostname ) );
		if( ret != 0 )
			return lst;

		hostaddr = gethostbyname( hostname );
		if( hostaddr == nullptr )
			return lst;

		while( hostaddr->h_addr_list[adapter_idx] )
		{
			memcpy( &address.sin_addr, hostaddr->h_addr_list[adapter_idx], hostaddr->h_length );

			lst.push_back( inet_ntoa( address.sin_addr ) );
			adapter_idx++;
		}
	}
	catch( ... )
	{
		puts( "get interface failed." );
	}

	return lst;
}

typedef void( *prase_fn )( const char* packet, size_t size );

void prase_packet( const char* packet, size_t size );
void prase_ip( const char* packet, size_t size );
void prase_tcp( const char* packet, size_t size );
void prase_pkg( const char* packet, size_t size, prase_fn decode );
void prase_pipe( const char* packet, size_t size );
void prase_msg( const char* packet, size_t size );

unsigned int	addr = INADDR_ANY;
unsigned short	port = INADDR_ANY;
char *msgbuf = nullptr;
unsigned int msglen = 0;

int main( int argc, char* argv[] )
{
	SOCKET			s = INVALID_SOCKET;
	WSABUF			wbuf = { 0 };
	DWORD			dwBytesRet = 0, dwFlags = 0;
	unsigned int	optval = 0;
	char			rcvbuf[1024*16];
	int				rc = 0, err;
	int idx = 0;
	int sel = 0;

	WSADATA wsaData;
	WSAStartup( MAKEWORD( 2, 2 ), &wsaData );

	if( argc > 1 )
		port = htons( (unsigned short)atoi( argv[1] ) );

	if( argc > 2 )
		addr = inet_addr( argv[2] );

	auto vec = getInterfaces();
	if( vec.size() > 1 )
	{
		puts( "choice one interface: " );
		for( auto iter = vec.begin(); iter != vec.end(); ++iter )
		{
			printf( "%d. %s\n", idx++, iter->c_str() );
		}
		puts( "q. exit" );
		do
		{
			sel = _getch();
			if( sel == 'q' || sel == 'Q' || sel == 27 )
				return -1;

			if( isdigit( sel ) )
			{
				sel -= '0';
				if( sel < (int)vec.size() )
					break;
			}

		} while( true );
	}
	//
	// Create a raw socket for receiving IP datagrams
	//
	s = WSASocket( AF_INET, SOCK_RAW, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED );
	if( s == INVALID_SOCKET )
	{
		printf( "WSASocket() failed: %d\n", WSAGetLastError() );
		return false;
	}

	//
	// This socket MUST be bound before calling the ioctl
	//

	sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr( vec[sel].c_str() );
	sa.sin_port = port;

	rc = bind( s, (SOCKADDR *)&sa, sizeof( sa ) );
	if( rc == SOCKET_ERROR )
	{
		printf( "bind() failed: %d\n", WSAGetLastError() );
		if( INVALID_SOCKET != s )
		{
			closesocket( s );
			s = INVALID_SOCKET;
		}
		WSACleanup();
		return false;
	}
	printf( "Binding to: " );
	//PrintAddress((SOCKADDR *)&g_saLocalInterface, sizeof(g_saLocalInterface));
	printf( "\n" );

	//
	// Set the SIO_RCVALLxxx ioctl
	//
	optval = 1;
	rc = WSAIoctl( s, SIO_RCVALL, &optval, sizeof( optval ),
		NULL, 0, &dwBytesRet, NULL, NULL );
	if( rc == SOCKET_ERROR )
	{
		printf( "WSAIotcl(0x%x) failed: %d\n", SIO_RCVALL,
			( err = WSAGetLastError() ) );
		if( err == WSAEINVAL )
		{
			printf( "NOTE: IPv6 does not currently support the SIO_RCVALL* ioctls\n" );
		}

		if( INVALID_SOCKET != s )
		{
			closesocket( s );
			s = INVALID_SOCKET;
		}
		WSACleanup();
		return false;
	}

	msgbuf = (char*)malloc( 1024 * 1024 * 16 );
	while( true )
	{
		wbuf.len = sizeof(rcvbuf);
		wbuf.buf = rcvbuf;
		dwFlags = 0;

		rc = WSARecv( s, &wbuf, 1, &dwBytesRet, &dwFlags, NULL, NULL );
		if( rc == SOCKET_ERROR )
		{
			printf( "WSARecv() failed: %d\n", WSAGetLastError() );
			break;
		}

		prase_ip( rcvbuf, dwBytesRet );

		if( _kbhit() )
		{
			int ch = _getch();
			if( ch == 27 )
				break;
		}
	}
	free( msgbuf );
	return 0;
}

struct value_string
{
	char*	string;
	int		value;
};

value_string _Protocal[] =
{
	{ "HOPOPTS", 0 },// IPv6 Hop-by-Hop options
	{ "ICMP", 1 },
	{ "IGMP", 2 },
	{ "GGP", 3 },
	{ "IPV4", 4 },
	{ "ST", 5 },
	{ "TCP", 6 },
	{ "CBT", 7 },
	{ "EGP", 8 },
	{ "IGP", 9 },
	{ "PUP", 12 },
	{ "UDP", 17 },
	{ "IDP", 22 },
	{ "RDP", 27 },
	{ "IPV6", 41 }, // IPv6 header
	{ "ROUTING", 43 }, // IPv6 Routing header
	{ "FRAGMENT", 44 }, // IPv6 fragmentation header
	{ "ESP", 50 }, // encapsulating security payload
	{ "AH", 51 }, // authentication header
	{ "ICMPV6", 58 }, // ICMPv6
	{ "NONE", 59 }, // IPv6 no next header
	{ "DSTOPTS", 60 }, // IPv6 Destination options
	{ "ND", 77 },
	{ "ICLFXBM", 78 },
	{ "PIM", 103 },
	{ "PGM", 113 },
	{ "L2TP", 115 },
	{ "SCTP", 132 },
	{ "RAW", 255 },
	{ "MAX", 256 },
	{ nullptr, 0 },
};

const char* search_string( int value, value_string* table )
{
	for( int i = 0; table && table[i].string; ++i )
	{
		if( table[i].value == value )
			return table[i].string;
	}

	return "";
}
void prase_ip( const char* packet, size_t size )
{
	// Check the IP version
	int ip_version	= HI_BYTE( *packet );
	int ip_header	= LO_BYTE( *packet ) * 4;
	puts( "=======================================================" );
	if( ip_version == 4 )
	{

		// Verify the buffer is large enough
		if( size  < sizeof( IPV4_HDR ) )
			return;

		IPV4_HDR header = *(IPV4_HDR *)packet;

		printf( "IPV%d\n", ip_version );
		puts( "=======================================================" );

		printf( "tos : %8d | tol : %8d | unq : %08x | offset : %d\n", 
			header.ip_tos, header.ip_totallength, header.ip_id, header.ip_offset );

		printf( "ttl : %8d | ptl : %8s | cks : %08x \n",
			header.ip_ttl, 
			search_string( header.ip_protocol, _Protocal ), 
			header.ip_checksum );

		IN_ADDR src, dst;
		src.S_un.S_addr = header.ip_srcaddr;
		dst.S_un.S_addr = header.ip_dstaddr;

		printf( "src(%s) <==> dst(%s)\n", inet_ntoa( src ), inet_ntoa( dst ) );

		switch( header.ip_protocol )
		{
		case IPPROTO_TCP:
			puts( "====================== TCP =============================" );
			prase_tcp( packet + ip_header, size - ip_header );
			break;
		case IPPROTO_UDP:
			break;
		}
	}
}

void prase_tcp( const char* packet, size_t size )
{
	TCP_HDR tcp = *(TCP_HDR*)packet;
	printf( "src(%d) <==> dst(%d)\n", ntohs( tcp.src_port ), ntohs( tcp.dst_port ) );
	printf( "seq : %8d | ack : %8d | " );

	prase_pkg( packet + sizeof( tcp ), size - sizeof( tcp ), prase_msg );
}

void prase_pkg( const char* packet, size_t size, prase_fn decode )
{
	memcpy( msgbuf + msglen, packet, size );
	msglen += size;

	if( msglen >= sizeof( unsigned short ) )
	{
		unsigned short mark = ntohs( *(unsigned short*)packet );

		if( mark == 0xaaee && msglen >= sizeof(pkghead16) )
		{
			// head16
			pkghead16 head	= *(pkghead16*)msgbuf;
			head.mark = ntohs( head.mark );
			head.length = ntohs( head.length );
			head.checksum = ntohs( head.checksum );

			if( msglen >= head.length )
			{
				decode( msgbuf, head.length );
				memmove( msgbuf, msgbuf + head.length + sizeof(pkghead16), msglen - head.length - sizeof(pkghead16) );
				msglen = msglen - head.length - sizeof( head );
			}
		}
		else if( mark == 0xaaef )
		{
			// head32
			pkghead32 head	= *(pkghead32*)msgbuf;
			head.mark = ntohs( head.mark );
			head.length = ntohl( head.length );
			head.checksum = ntohs( head.checksum );

			if( msglen >= sizeof(head) + head.length )
			{
				decode( msgbuf + sizeof( head ), msglen - sizeof( head ) );
				memmove( msgbuf, msgbuf + head.length + sizeof(head), msglen - head.length - sizeof(head) );
				msglen = msglen - head.length - sizeof( head );
			}
		}
		else
		{
			return;
		}
	}
}

#define ID_CONNECT_REQ	1
#define ID_CONNECT_ACK	2
#define ID_DATA			10
#define ID_PING			11

#define DATA_MARK		0x66bb

void prase_pipe( const char* packet, size_t size )
{
	unsigned short msgid = htons( *(unsigned short*)packet );
	switch( msgid )
	{
	case ID_CONNECT_REQ:
		break;
	case ID_CONNECT_ACK:
		break;
	case ID_DATA:
		{
			if( size < sizeof( data_header ) )
				return;

			data_header head = *(data_header*)packet;
			head.business = ntohs( head.business );
			head.length = ntohs( head.length );
			head.mark = ntohs( head.mark );

			if( head.mark != DATA_MARK )
				return;

			if( head.length != size - sizeof( data_header ) )
				return;

			prase_msg( packet + sizeof( data_header ), size - sizeof( data_header ) );
			break;
		}
	case ID_PING:
		break;
	}
}

void prase_msg( const char* packet, size_t size )
{
	if( size < sizeof( pkghead ) + sizeof( msghead ) )
		return;

	pkghead pkg = *(pkghead*)( packet );
	msghead msg = *(msghead*)( packet + sizeof(pkg) );

	packet += sizeof(pkg)+sizeof(msg);
	size -= sizeof(pkg)+sizeof( msg );

	pkg._length = ntohs( pkg._length );

	msg._class = ntohs( msg._class );
	msg._message = ntohs( msg._message );

}