#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>
#include <vector>
namespace crypto_hash {
	class plot_builder
	{
		HWND canvas;
		HDC context;
		uint16_t hSpace, vSpace;
		uint16_t padding;
		bool init;
		struct __border_t {
			POINT leftTop, leftBottom,
				rightTop, rightBottom;
		} border;
		std::vector<POINT> axes_data;
		std::vector<POINT> plot_data;
	public:
		plot_builder();
		plot_builder(HWND);
		~plot_builder();

		void set_canvas(HWND);
		void set_hSpace(uint16_t);
		void set_vSpace(uint16_t);
		
	};
}
