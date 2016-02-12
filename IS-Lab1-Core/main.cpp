#pragma warning (disable : 4996)

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <windowsx.h>
#include <CommCtrl.h>
#include <commdlg.h>
#include <cstring>
#include <tchar.h>
#include <thread>

#include "ctrldefines.h"

#pragma comment (lib, "comctl32")
#pragma comment (linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

LRESULT CALLBACK WndProcFunc(HWND, UINT, WPARAM, LPARAM);
BOOL FOpenDialogExecute(HWND, LPWSTR);

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
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
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
	static HWND hWndEditFName, hWndBtnOFile;
	static WCHAR hashingFile[FILENAME_MAX + 1];
	switch (msg) 
	{
	case WM_CREATE:
		hWndEditFName = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", NULL, 
			WS_CHILD | WS_VISIBLE | ES_LEFT | ES_READONLY | ES_AUTOHSCROLL, 
			10, 10, 300, 25, hWnd, (HMENU)ID_EDIT_FILENAME, 
			(HINSTANCE) GetWindowLong(hWnd, GWL_HINSTANCE), NULL);

		if (hWndEditFName == 0) {
			MessageBox(hWnd, L"Ошибка при создании элемента", L"IS Lab 1", MB_OK | MB_ICONEXCLAMATION);
			PostQuitMessage(1);
		}
		hWndBtnOFile = CreateWindowEx(0, L"BUTTON", L"Открыть файл",
			WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 320, 10, 125, 25, hWnd,
			(HMENU)ID_BUTTON_OPENFILE, (HINSTANCE) GetWindowLong(hWnd, GWL_HINSTANCE), NULL);
		if (hWndBtnOFile == 0) {
			MessageBox(hWnd, L"Ошибка при создании элемента", L"IS Lab 1", MB_OK | MB_ICONEXCLAMATION);
			PostQuitMessage(1);
		}
		break;
	case WM_COMMAND:
		switch (LOWORD(wParam)) 
		{
		case ID_BUTTON_OPENFILE: 
			if (FOpenDialogExecute(hWnd, hashingFile)) {
				SendMessage(hWndEditFName, WM_SETTEXT, 0, (LPARAM)hashingFile);
			}
			else {
				SendMessage(hWndEditFName, WM_SETTEXT, 0, (LPARAM) L"");
			}
			break;
		}
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, msg, wParam, lParam);
		break;
	}
	return FALSE;
}

BOOL FOpenDialogExecute(HWND hWndOwner, LPWSTR fName) {
	OPENFILENAME ofn;
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = hWndOwner;
	ofn.lpstrFile = fName;
	ofn.lpstrFile[0] = L'\0';
	ofn.nMaxFile = FILENAME_MAX;
	ofn.lpstrFilter = L"Все файлы\0*.*\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_DONTADDTORECENT | OFN_FORCESHOWHIDDEN | OFN_NONETWORKBUTTON;
	ofn.lpstrFileTitle = L"Открыть файл, для получения хеш-функции...";
	if (GetOpenFileName(&ofn) == TRUE) {
		return TRUE;
	}
	return FALSE;	
}