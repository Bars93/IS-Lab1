#include "plot_builder.h"

namespace winGDI {


	plot_builder::plot_builder() :
		canvas(NULL), context(NULL), 
		hSpace(10), vSpace(10), 
		padding(15), init(false)
	{
	}
	plot_builder::plot_builder(HWND _canvas) :
		canvas(_canvas), context(NULL),
		hSpace(10), vSpace(10), 
		padding(15), init(false)
	{
	}

	plot_builder::~plot_builder()
	{
	}


}