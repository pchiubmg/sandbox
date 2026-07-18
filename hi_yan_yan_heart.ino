/**************************************************************************
 This is an example for our Monochrome OLEDs based on SSD1306 drivers

 Pick one up today in the adafruit shop!
 ------> http://www.adafruit.com/category/63_98

 This example is for a 128x32 pixel display using I2C to communicate
 3 pins are required to interface (two I2C and one reset).

 Adafruit invests time and resources providing this open
 source code, please support Adafruit and open-source
 hardware by purchasing products from Adafruit!

 Written by Limor Fried/Ladyada for Adafruit Industries,
 with contributions from the open source community.
 BSD license, check license.txt for more information
 All text above, and the splash screen below must be
 included in any redistribution.
 **************************************************************************/

#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306_EMULATOR.h>
#include <SPI.h>
#include <Wire.h>

#define SCREEN_WIDTH 128  // OLED display width, in pixels
#define SCREEN_HEIGHT 32  // OLED display height, in pixels

// Declaration for an SSD1306 display connected to I2C (SDA, SCL pins)
// The pins for I2C are defined by the Wire-library.
// On an arduino UNO:       A4(SDA), A5(SCL)
// On an arduino MEGA 2560: 20(SDA), 21(SCL)
// On an arduino LEONARDO:   2(SDA),  3(SCL), ...
#define OLED_RESET -1  // Reset pin # (or -1 if sharing Arduino reset pin)
#define SCREEN_ADDRESS \
  0x3C  ///< See datasheet for Address; 0x3D for 128x64, 0x3C for 128x32
Adafruit_SSD1306_EMULATOR display(SCREEN_WIDTH,
                                  SCREEN_HEIGHT,
                                  &Wire,
                                  OLED_RESET);

// A little 16x16 heart we can fling around the screen.
#define HEART_WIDTH 16
#define HEART_HEIGHT 16
static const unsigned char PROGMEM heart_bmp[] = {
    0b00000000, 0b00000000, 0b01110000, 0b00001110, 0b11111000, 0b00011111,
    0b11111100, 0b00111111, 0b11111110, 0b01111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111, 0b01111111, 0b11111110,
    0b00111111, 0b11111100, 0b00011111, 0b11111000, 0b00001111, 0b11110000,
    0b00000111, 0b11100000, 0b00000011, 0b11000000, 0b00000001, 0b10000000,
    0b00000000, 0b00000000};

#define NUM_HEARTS 8  // Floating hearts in the rising-hearts scene

void setup() {
  Serial.begin(9600);

  // SSD1306_SWITCHCAPVCC = generate display voltage from 3.3V internally
  if (!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
    Serial.println(F("SSD1306 allocation failed"));
    for (;;)
      ;  // Don't proceed, loop forever
  }

  display.clearDisplay();
  display.display();
}

// The whole show loops forever: an animated intro, a beating heart with the
// message, a flurry of rising hearts, and a big scrolling "I love you".
void loop() {
  introSparkle();       // Draw-in border + starbursts using lines/circles
  beatingHeart();       // Pulsing heart next to "I love you Yan Yan"
  risingHearts();       // Little hearts floating up the screen
  scrollLoveMessage();  // Big 2x text sweeping across
}

// ---------------------------------------------------------------------------
// Scene 1: an animated border draws itself in, with sparkle bursts.
// Shows off drawLine, drawRect, drawRoundRect and drawCircle.
// ---------------------------------------------------------------------------
void introSparkle() {
  display.clearDisplay();

  // Sweep a rounded frame inward, one ring at a time.
  for (int16_t i = 0; i < 6; i += 2) {
    display.drawRoundRect(i, i, display.width() - 2 * i,
                          display.height() - 2 * i, 6, SSD1306_WHITE);
    display.display();
    delay(120);
  }

  // A few starbursts: rays shooting out from random points.
  for (uint8_t s = 0; s < 4; s++) {
    int16_t cx = random(16, display.width() - 16);
    int16_t cy = random(8, display.height() - 8);
    for (int16_t r = 1; r <= 6; r++) {
      display.drawLine(cx, cy, cx + r, cy, SSD1306_WHITE);
      display.drawLine(cx, cy, cx - r, cy, SSD1306_WHITE);
      display.drawLine(cx, cy, cx, cy + r, SSD1306_WHITE);
      display.drawLine(cx, cy, cx, cy - r, SSD1306_WHITE);
      display.drawCircle(cx, cy, r, SSD1306_WHITE);
      display.display();
      delay(30);
    }
  }

  delay(400);
}

// ---------------------------------------------------------------------------
// Scene 2: a heart that beats (grows and shrinks) beside the message.
// Shows off fillCircle, fillTriangle and text rendering.
// ---------------------------------------------------------------------------
void beatingHeart() {
  // Radii for one "lub-dub" beat: swell up, settle, swell again.
  const int16_t beat[] = {8, 11, 9, 13, 10};
  const uint8_t frames = sizeof(beat) / sizeof(beat[0]);

  for (uint8_t rep = 0; rep < 3; rep++) {
    for (uint8_t f = 0; f < frames; f++) {
      display.clearDisplay();

      display.setTextSize(1);
      display.setTextColor(SSD1306_WHITE);
      display.setCursor(2, 6);
      display.println(F("I love you"));
      display.setCursor(2, 18);
      display.println(F("Yan Yan"));

      drawHeart(104, 16, beat[f]);  // Heart pulses on the right
      display.display();
      delay(90);
    }
  }

  delay(300);
}

// ---------------------------------------------------------------------------
// Scene 3: little hearts drift up the screen, like the snowflake demo but
// happier. Shows off drawBitmap animation.
// ---------------------------------------------------------------------------
void risingHearts() {
  int16_t x[NUM_HEARTS], y[NUM_HEARTS], dy[NUM_HEARTS];

  for (uint8_t i = 0; i < NUM_HEARTS; i++) {
    x[i] = random(0, display.width() - HEART_WIDTH);
    y[i] = random(display.height(), display.height() + 40);
    dy[i] = random(1, 4);  // Rise speed
  }

  for (uint8_t step = 0; step < 60; step++) {
    display.clearDisplay();
    for (uint8_t i = 0; i < NUM_HEARTS; i++) {
      display.drawBitmap(x[i], y[i], heart_bmp, HEART_WIDTH, HEART_HEIGHT,
                         SSD1306_WHITE);
      y[i] -= dy[i];
      // Recycle a heart once it floats off the top.
      if (y[i] < -HEART_HEIGHT) {
        x[i] = random(0, display.width() - HEART_WIDTH);
        y[i] = display.height();
        dy[i] = random(1, 4);
      }
    }
    display.display();
    delay(60);
  }
}

// ---------------------------------------------------------------------------
// Scene 4: the big finale message slides across the screen, then uses the
// SSD1306 hardware scroll for a little sparkle. Shows off setTextSize + scroll.
// ---------------------------------------------------------------------------
void scrollLoveMessage() {
  const char message[] = "I love you Yan Yan  <3 <3 <3   ";
  display.setTextSize(2);  // 2x tall text (each glyph is 12x16)
  display.setTextColor(SSD1306_WHITE);

  int16_t textPixels = (int16_t)strlen(message) * 12;

  // Slide the string in from the right and off to the left.
  for (int16_t x = display.width(); x > -textPixels; x -= 4) {
    display.clearDisplay();
    display.setCursor(x, 8);
    display.print(message);
    display.display();
    delay(20);
  }

  // Park a heart in the middle and let the hardware scroll shimmer it.
  display.clearDisplay();
  drawHeart(display.width() / 2, display.height() / 2, 12);
  display.display();
  display.startscrollright(0x00, 0x03);
  delay(1500);
  display.stopscroll();
  delay(300);
}

// Draw a filled heart centered at (cx, cy) sized by `r`.
// A heart is two circles side-by-side sitting on top of a triangle.
void drawHeart(int16_t cx, int16_t cy, int16_t r) {
  int16_t offset = r / 2;

  // The two rounded lobes at the top.
  display.fillCircle(cx - offset, cy - offset, offset, SSD1306_WHITE);
  display.fillCircle(cx + offset, cy - offset, offset, SSD1306_WHITE);

  // The pointed bottom.
  display.fillTriangle(cx - r, cy - offset,   // left edge
                       cx + r, cy - offset,   // right edge
                       cx, cy + r,            // bottom point
                       SSD1306_WHITE);
}
