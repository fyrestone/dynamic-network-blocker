/*!
\file ColorPrint.h
\author LiuBao
\version 1.0
\date 2010/12/28
\brief Windows控制台彩色输出接口及色彩定义
*/
#ifndef COLOR_PRINT
#define COLOR_PRINT

#include <tchar.h>    /* 使用_TCHAR */

typedef enum _COLOR   ///  色彩定义
{
    BLACK,            ///< 黑色
    NAVY,             ///< 深蓝色
    GREEN,            ///< 绿色
    TEAL,             ///< 青色
    MAROON,           ///< 褐红色
    PURPLE,           ///< 紫色
    OLIVE,            ///< 橄榄绿
    SILVER,           ///< 银色
    GRAY,             ///< 灰色
    BLUE,             ///< 蓝色
    LIME,             ///< 黄绿色
    AQUA,             ///< 浅绿色
    RED,              ///< 红色
    FUCHSIA,          ///< 紫红色
    YELLOW,           ///< 黄色
    WHITE             ///< 白色
}COLOR;

#ifdef _UNICODE
#define ColorPrintf ColorPrintfW
#else
#define ColorPrintf ColorPrintfA
#endif

/*!
控制台彩色输出，在printf基础上增加颜色选择（Unicode版本）
\param color 输出颜色
\param format 输出格式，同printf
\return 写入的字符数量，出错返回负值，同printf
*/
int ColorPrintfW(COLOR color, const wchar_t *format, ...);

/*!
控制台彩色输出，在printf基础上增加颜色选择（ANSI版本）
\param color 输出颜色
\param format 输出格式，同printf
\return 写入的字符数量，出错返回负值，同printf
*/
int ColorPrintfA(COLOR color, const char *format, ...);

/*!
按颜色名打印所有色彩，用于测试色彩输出
*/
void PrintAllColor();

#endif