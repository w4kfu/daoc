#include "daoc.h"
 
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libtomcrypt.lib")
 
#define WM_SOCKET (WM_USER + 1)

HWND MakeWorkerWindow(void);
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

HWND Window;
struct Packet packet;
struct InfoCon info;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	SOCKET sock;
	char buf[200];
	int result;
	int pos;
	char actual;

	if (uMsg == WM_SOCKET)
	{
		if (WSAGETSELECTERROR(lParam))
		{
			printf("[-] Socket failed with error %d\n", WSAGETSELECTERROR(lParam));
			exit(EXIT_FAILURE);
		}
		else
		{
			sock = (SOCKET)wParam;
			switch (WSAGETSELECTEVENT(lParam))
			{
				case FD_ACCEPT:
					printf("FD_ACCEPT!\n");
					break;
				case FD_READ:
					printf("FD_READ!\n");
					memset(buf, 0, sizeof (buf));
					result = recv(sock, buf, 200, 0);
					hex_dump(buf, 200);
					if (result == -1)
					{
						result = WSAGetLastError();
						if (result != WSAEWOULDBLOCK)
						{
							printf("[-] recv() : %d\n" , WSAGetLastError());
							exit(EXIT_FAILURE);
						}
					}
					else
					{
						if (result > 0)
						{
							pos = 0;
							do
							{
								actual = buf[pos++];
								if (packet.NS_IsConnect)
								{
									if (actual == 0x1B)
									{
									  if (packet.field_28)
									  {
									    packet.field_28 = 0;
									    packet.NS_IsConnect = 0;
									    packet.field_1C = 2;
									    packet.LengthPacket = 0;
									  }
									  else
									  {
									    packet.field_28 = 1;
									  }
									}
								}
								else
								{
								  int v9, v10;
								  *(&packet.field_141 + packet.field_1C++) = actual;
								  v9 = packet.field_1C;
								  if (v9 == 4)
								  {
								    v10 = ROL16(packet.field_143, 8);
								    packet.LengthPacket = v10 + 4;
								  }
								  if (v9 == packet.LengthPacket)
								  {
								    packet.NS_IsConnect = 1;
								    packet.field_28 = 0;
									ParsePacket(&info, &packet);
								  }
								}
							} while (pos < result);
						}
					}
					break;
            case FD_WRITE:
					printf("FD_WRITE!\n");
					break;
            case FD_CLOSE:
					printf("FD_CLOSE!\n");
					break;
			case FD_CONNECT:
					printf("FD_CONNECT!\n");
					memset(&packet, 0, sizeof (struct Packet));
					packet.field_1C = 0;
					packet.LengthPacket = 0;
					packet.NS_IsConnect = 1;
					packet.field_28 = 0;
					if (WSAAsyncSelect(sock, Window, WM_SOCKET, FD_READ | FD_CLOSE) == -1)
					{
					    printf("Could not WSAAsyncSelect : %d\n" , WSAGetLastError());
						exit(EXIT_FAILURE);
					}
					break;
			case FD_OOB:
					printf("FD_OOB!\n");
					break;
			case FD_QOS:
					printf("FD_QOS!\n");
					break;
			default:
					printf("[-] NOT HANDLED !\n");
					break;
			}
		}
	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

HWND MakeWorkerWindow(void)
{
	WNDCLASS wndclass;
	CHAR *ProviderClass = "WUT";
	HWND Window;
 
	wndclass.style = CS_HREDRAW | CS_VREDRAW;
	wndclass.lpfnWndProc = (WNDPROC)WindowProc;
	wndclass.cbClsExtra = 0;
	wndclass.cbWndExtra = 0;
	wndclass.hInstance = NULL;
	wndclass.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wndclass.hCursor = LoadCursor(NULL, IDC_ARROW);
	wndclass.hbrBackground = (HBRUSH) GetStockObject(WHITE_BRUSH);
	wndclass.lpszMenuName = NULL;
	wndclass.lpszClassName = (LPCWSTR)ProviderClass;
 
	if (RegisterClass(&wndclass) == 0)
	{
		printf("RegisterClass() failed with error %d\n", GetLastError());
		return NULL;
	}
	else
		printf("RegisterClass() is OK!\n");
 
	if ((Window = CreateWindow(
				(LPCWSTR)ProviderClass,
				L"",
				WS_OVERLAPPEDWINDOW,
				CW_USEDEFAULT,
				CW_USEDEFAULT,
				CW_USEDEFAULT,
				CW_USEDEFAULT,
				NULL,
				NULL,
				NULL,
				NULL)) == NULL)
	{
		printf("CreateWindow() failed with error %d\n", GetLastError());
		return NULL;
	}
	else
		printf("CreateWindow() is OK!\n");
	return Window;
}

int main(int argc , char *argv[])
{
	WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
	u_long argp;
	char optval[4];
	int error_res;
	MSG msg;
	DWORD Ret;

	memset(&info, 0, sizeof (struct InfoCon));

	Window = MakeWorkerWindow();

    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
        printf("Failed. Error Code : %d\n",WSAGetLastError());
        return 1;
    }
    printf("[+] Winsock initialised\n");
    if ((sock = socket(AF_INET, SOCK_STREAM , 0)) == INVALID_SOCKET)
    {
        printf("Could not create socket : %d\n" , WSAGetLastError());
		exit(EXIT_FAILURE);
    }
    printf("[+] Socket created\n");
	argp = 1;
	*(DWORD*)optval = 1;
	ioctlsocket(sock, FIONBIO, &argp);
    setsockopt(sock, 6, 1, optval, 4);
    setsockopt(sock, 6, 0xFFFFFF7Fu, optval, 4);
	if (WSAAsyncSelect(sock, Window, WM_SOCKET, FD_CONNECT) == -1)
	{
        printf("Could not WSAAsyncSelect : %d\n" , WSAGetLastError());
		exit(EXIT_FAILURE);
	}
    server.sin_addr.s_addr = inet_addr("107.23.177.195");
    server.sin_family = AF_INET;
    server.sin_port = htons(10501);
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) != -1)
    {
        printf("Could not connect : %d\n" , WSAGetLastError());
        exit(EXIT_FAILURE);
    }
	error_res = WSAGetLastError();
	if (error_res != WSAEWOULDBLOCK)
	{
        printf("Could not connect : %d\n" , WSAGetLastError());
        exit(EXIT_FAILURE);
	}
    printf("[+] Connected !\n");
	info.sock = sock;
	while (Ret = GetMessage(&msg, NULL, 0, 0))
	{
		if (Ret == -1)
		{
			printf("\nGetMessage() failed with error %d\n", GetLastError());
			return 1;
		}
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	closesocket(sock);
    return 0;
}