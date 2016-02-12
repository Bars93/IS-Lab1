#pragma warning (disable : 4996)

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <windowsx.h>
#include <CommCtrl.h>
#include <cstdio>
#include <cstring>
#include <tchar.h>
#include <thread>

#pragma comment (lib, "comctl32")

LRESULT CALLBACK WndProcFunc(HWND, UINT, WPARAM, LPARAM);

int WINAPI WinMain(
	HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR lpCmdLine,
	int nCmdShow
	)
{
	WNDCLASSEX wcex;
	LPCWSTR szWindowClass = L"IS-Lab1";
	LPCWSTR szTitle = L"IS Lab 1";
	INITCOMMONCONTROLSEX InitCtrls;
	HWND hWinHandle;
	const DWORD dwStyle = (WS_OVERLAPPEDWINDOW ^ (WS_THICKFRAME | WS_MAXIMIZEBOX)) | WS_CLIPSIBLINGS | WS_CLIPCHILDREN ;
	const DWORD dwStyleEx = WS_EX_APPWINDOW | WS_EX_WINDOWEDGE;
	MSG msgStorage = { 0 };

	ZeroMemory(&wcex, sizeof(WNDCLASSEX));
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.lpfnWndProc = (WNDPROC) WndProcFunc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APPLICATION));
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW);
	wcex.lpszMenuName = NULL;
	wcex.lpszClassName = szWindowClass;
	wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_APPLICATION));

	if (!RegisterClassEx(&wcex)) {
		MessageBox(NULL, _T("Ошибка в регистрации класса окна!"), _T("IS Lab 1"), MB_OK | MB_ICONEXCLAMATION);
		return 1;
	}

	InitCtrls.dwSize = sizeof(INITCOMMONCONTROLSEX);
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);
	hWinHandle = CreateWindowEx(dwStyleEx, szWindowClass, szTitle, dwStyle, 100, 100, 600, 400, NULL, NULL, hInstance, (LPVOID)NULL);
	ShowWindow(hWinHandle, nCmdShow);
	UpdateWindow(hWinHandle);
	while (GetMessage(&msgStorage, NULL, 0, 0)) {
		TranslateMessage(&msgStorage);
		DispatchMessage(&msgStorage);
	}
	return msgStorage.wParam;
}

LRESULT CALLBACK WndProcFunc(
	HWND hWnd, 
	UINT msg, 
	WPARAM wParam, 
	LPARAM lParam
	)
{
	switch (msg) {
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, msg, wParam, lParam);
		break;
	}
}