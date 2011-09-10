/*!
\file ColorPrint.c
\author LiuBao
\version 1.0
\date 2010/12/28
\brief Windows控制台彩色输出函数实现
*/
#include "stdafx.h"
#include "ColorPrint.h"

int ColorPrintfW(COLOR color, const wchar_t *format, ...)
{
    int retVal;

    va_list ap;
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);

    (void)SetConsoleTextAttribute(hCon, color|0);
    va_start(ap, format);//初始化ap。

    retVal = vwprintf(format, ap);

    va_end(ap);//清理ap。
    (void)SetConsoleTextAttribute(hCon, SILVER|0);

    return retVal;
}

int ColorPrintfA(COLOR color, const char * format, ...)
{
    int retVal;

    va_list ap;
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);

    (void)SetConsoleTextAttribute(hCon, color|0);
    va_start(ap, format);//初始化ap。

    retVal = vprintf(format, ap);

    va_end(ap);//清理ap。
    (void)SetConsoleTextAttribute(hCon, SILVER|0);

    return retVal;
}

void PrintAllColor()
{
    int i;
    const _TCHAR *colorName[] = 
    {
        _T("BLACK"), _T("NAVY"), _T("GREEN"), _T("TEAL"), _T("MAROON"), 
        _T("PURPLE"), _T("OLIVE"), _T("SILVER"), _T("GRAY"), _T("BLUE"),
        _T("LIME"), _T("AQUA"), _T("RED"), _T("FUCHSIA"),_T("YELLOW"), 
        _T("WHITE")
    };

    for(i = 0 ; i < sizeof(colorName) / sizeof(colorName[0]) ; ++i)
        ColorPrintf((COLOR)i, _T("%s\n"), colorName[i]);
}