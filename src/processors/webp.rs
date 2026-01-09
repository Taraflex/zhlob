#![allow(unsafe_op_in_unsafe_fn)]

use crate::{cli::CLI, maybe::UnifiedError};
use image::{GrayAlphaImage, GrayImage, imageops::FilterType};
use libwebp_sys::*;
use std::{ptr, sync::OnceLock};

pub fn thumbnail(data: Vec<u8>) -> Result<Vec<u8>, UnifiedError> {
    let mut img = image::load_from_memory(&data)?;
    drop(data);

    let (ow, oh) = (img.width(), img.height());
    let min_orig = ow.min(oh) as f32;

    let cli = &*CLI;

    let min: f32 = cli.image_scale_limit[0] as f32;
    let max: f32 = cli.image_scale_limit[1] as f32;
    let mut ratio: f32 = cli.image_scale;

    if min_orig * ratio < min {
        ratio = min / min_orig;
    }
    if min_orig * ratio > max {
        ratio = max / min_orig;
    }

    if ratio > 1.0 {
        ratio = 1.0;
    }

    let nw = (ow as f32 * ratio).round() as u32;
    let nh = (oh as f32 * ratio).round() as u32;

    if nw != ow || nh != oh {
        let i = img.resize_exact(nw, nh, FilterType::CatmullRom);
        drop(img);
        img = i;
    }

    let res = if img.color().has_alpha() {
        let luma = img.to_luma_alpha8();
        drop(img);
        encode_gray_alpha(&luma)?
    } else {
        let luma = img.to_luma8();
        drop(img);
        encode_gray(&luma)?
    };

    Ok(res)
}

/// Кодирует GrayImage (Luma8)
fn encode_gray(img: &GrayImage) -> Result<Vec<u8>, String> {
    unsafe {
        let mut picture = init_picture(img.width(), img.height(), false)?;

        // Копируем Y канал
        copy_y_plane(&mut picture, img.as_raw());

        // Заполняем UV нейтральным цветом
        fill_uv_planes(&mut picture);

        execute_encode(&mut picture)
    }
}

/// Кодирует GrayAlphaImage (LumaA8)
fn encode_gray_alpha(img: &GrayAlphaImage) -> Result<Vec<u8>, String> {
    unsafe {
        let mut picture = init_picture(img.width(), img.height(), true)?;

        let raw = img.as_raw();
        let width = picture.width as usize;
        let height = picture.height as usize;

        // Извлекаем Y и A из чередующегося буфера [L, A, L, A...]
        for y in 0..height {
            let y_offset = y * picture.y_stride as usize;
            let a_offset = y * picture.a_stride as usize;
            let src_row_offset = y * width * 2;

            for x in 0..width {
                let luma = raw[src_row_offset + x * 2];
                let alpha = raw[src_row_offset + x * 2 + 1];

                *picture.y.add(y_offset + x) = luma;
                *picture.a.add(a_offset + x) = alpha;
            }
        }

        fill_uv_planes(&mut picture);
        execute_encode(&mut picture)
    }
}

// --- Приватные вспомогательные функции ---

unsafe fn init_picture(w: u32, h: u32, has_alpha: bool) -> Result<WebPPicture, String> {
    let mut picture = WebPPicture::new().map_err(|_| "WebPPictureInit failed")?;
    picture.width = w as i32;
    picture.height = h as i32;
    picture.use_argb = 0;

    picture.colorspace = if has_alpha {
        WebPEncCSP::WEBP_YUV420A
    } else {
        WebPEncCSP::WEBP_YUV420
    };

    if WebPPictureAlloc(&mut picture) == 0 {
        Err("WebPPictureAlloc failed".into())
    } else {
        Ok(picture)
    }
}

unsafe fn copy_y_plane(picture: &mut WebPPicture, raw_y: &[u8]) {
    for y in 0..picture.height as usize {
        let src_ptr = raw_y.as_ptr().add(y * picture.width as usize);
        let dst_ptr = picture.y.add(y * picture.y_stride as usize);
        ptr::copy_nonoverlapping(src_ptr, dst_ptr, picture.width as usize);
    }
}

unsafe fn fill_uv_planes(picture: &mut WebPPicture) {
    let uv_width = (picture.width + 1) / 2;
    let uv_height = (picture.height + 1) / 2;
    for y in 0..uv_height as usize {
        let u_ptr = picture.u.add(y * picture.uv_stride as usize);
        let v_ptr = picture.v.add(y * picture.uv_stride as usize);
        ptr::write_bytes(u_ptr, 128, uv_width as usize);
        ptr::write_bytes(v_ptr, 128, uv_width as usize);
    }
}

unsafe fn execute_encode(picture: &mut WebPPicture) -> Result<Vec<u8>, String> {
    static CONFIG: OnceLock<WebPConfig> = OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        let mut config = WebPConfig::new().unwrap();

        // --- СКОРОСТЬ И ПРОИЗВОДИТЕЛЬНОСТЬ ---
        config.method = 3; // Баланс (0-6). 3 дает хорошее сжатие без жора CPU.
        config.pass = 1; // 1 проход. Больше одного для прокси на лету — смерть.
        config.thread_level = 0; // Выключаем многопоточность для кодирования.
        config.low_memory = 1; // Включаем экономию памяти ради скорости.

        // --- ОСНОВНОЕ СЖАТИЕ (Цвет/Яркость) ---
        config.quality = 10.0; //18.0; // Чуть выше "минимума". Для ч/б и текста это ОК.
        config.image_hint = WebPImageHint::WEBP_HINT_GRAPH; // Лучший хинт для текста и интерфейсов.
        config.sns_strength = 60; // Усиливаем сохранение структуры (важно для букв).
        config.segments = 4; // Макс. сегментация для лучшего разделения текста и фона.

        // --- СОХРАНЕНИЕ ЧИТАЕМОСТИ (Text Sharpness) ---
        config.use_sharp_yuv = 1; // КРИТИЧНО для текста. Убирает "грязь" на границах букв.
        config.filter_strength = 25; // Умеренный деблокинг. Не мылим текст, но и не оставляем "кашу".
        config.filter_sharpness = 7; // Максимальная резкость фильтра (сохраняет грани букв).
        config.filter_type = 1; // Сложный фильтр. Лучше чистит артефакты низкого качества.

        // --- АЛЬФА-КАНАЛ (Сжатие "вдрызг") ---
        config.alpha_quality = 1; // Альфа-канал в минимальное качество (прозрачность будет грубой).
        config.alpha_compression = 1; // Включаем сжатие прозрачности.
        config.alpha_filtering = 0; // Самый простой и быстрый фильтр для альфы.

        // --- ДОПОЛНИТЕЛЬНО ---
        config.preprocessing = 0; // Отключаем размытие перед сжатием.
        config.exact = 0; // Разрешаем кодеру менять значения в невидимых областях.

        if WebPValidateConfig(&config) == 0 {
            panic!("Invalid webp config");
        }

        config
    });

    let mut writer_mem = std::mem::MaybeUninit::<WebPMemoryWriter>::uninit();
    WebPMemoryWriterInit(writer_mem.as_mut_ptr());
    let mut writer_mem: libwebp_sys::WebPMemoryWriter = writer_mem.assume_init();

    picture.writer = Some(WebPMemoryWrite);
    picture.custom_ptr = &mut writer_mem as *mut _ as *mut std::ffi::c_void;

    let result = if WebPEncode(config, picture) != 0 {
        WebPPictureFree(picture);
        Ok(Vec::from_raw_parts(
            writer_mem.mem,
            writer_mem.size as usize,
            writer_mem.max_size as usize,
        ))
    } else {
        let code = picture.error_code;
        WebPPictureFree(picture);
        WebPMemoryWriterClear(&mut writer_mem);
        Err(format!("WebPEncode failed with error: {:?}", code))
    };

    result
}
