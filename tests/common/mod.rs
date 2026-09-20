use image::{Rgb, RgbImage};
use lopdf::{Document, Object, Stream, dictionary};

pub fn screenshot(text: &str) -> RgbImage {
    let path =
        std::env::var("PREFLIGHT_TEST_FONT").expect("run tests through devenv for the pinned font");
    let font = fontdue::Font::from_bytes(
        std::fs::read(path).unwrap(),
        fontdue::FontSettings::default(),
    )
    .unwrap();
    let size = 40.0;
    let mut image = RgbImage::from_pixel(1400, 180, Rgb([255, 255, 255]));
    let mut pen = 40.0;
    for ch in text.chars() {
        let (metrics, bitmap) = font.rasterize(ch, size);
        for y in 0..metrics.height {
            for x in 0..metrics.width {
                let px = pen as i32 + metrics.xmin + x as i32;
                let py = 100 - metrics.height as i32 - metrics.ymin + y as i32;
                if px >= 0 && py >= 0 && (px as u32) < image.width() && (py as u32) < image.height()
                {
                    let v = 255 - bitmap[y * metrics.width + x];
                    image.put_pixel(px as u32, py as u32, Rgb([v, v, v]));
                }
            }
        }
        pen += metrics.advance_width;
    }
    image
}

pub fn scanned_pdf(image: &RgbImage) -> Vec<u8> {
    let mut doc = Document::with_version("1.5");
    let pages = doc.new_object_id();
    let image_id=doc.add_object(Stream::new(dictionary!{"Type"=>"XObject","Subtype"=>"Image","Width"=>image.width() as i64,"Height"=>image.height() as i64,"ColorSpace"=>"DeviceRGB","BitsPerComponent"=>8},image.as_raw().clone()));
    let content = doc.add_object(Stream::new(
        dictionary! {},
        format!(
            "q {} 0 0 {} 0 0 cm /Im0 Do Q",
            image.width(),
            image.height()
        )
        .into_bytes(),
    ));
    let page=doc.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"MediaBox"=>vec![0.into(),0.into(),(image.width() as i64).into(),(image.height() as i64).into()],"Resources"=>dictionary!{"XObject"=>dictionary!{"Im0"=>image_id}},"Contents"=>content});
    doc.objects.insert(
        pages,
        Object::Dictionary(
            dictionary! {"Type"=>"Pages","Kids"=>vec![Object::Reference(page)],"Count"=>1},
        ),
    );
    let catalog = doc.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
    doc.trailer.set("Root", catalog);
    doc.compress();
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    bytes
}
