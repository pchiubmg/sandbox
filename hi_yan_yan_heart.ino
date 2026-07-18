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

void setup() {
  Serial.begin(9600);

  // SSD1306_SWITCHCAPVCC = generate display voltage from 3.3V internally
  if (!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
    Serial.println(F("SSD1306 allocation failed"));
    for (;;)
      ;  // Don't proceed, loop forever
  }

  // Clear the splash screen the library starts with.
  display.clearDisplay();

  // Draw the greeting and the heart, then push it all to the screen at once.
  drawGreeting();
  drawHeart(104, 16, 12);  // Heart on the right side of the display

  display.display();
}

void loop() {}

// Print "Hi Yan Yan" on the left half of the display, vertically centered.
void drawGreeting() {
  display.setTextSize(1);               // Normal 1:1 pixel scale
  display.setTextColor(SSD1306_WHITE);  // Draw white text
  display.setCursor(4, 4);
  display.println(F("Hi Yan Yan"));
  display.setCursor(4, 18);
  display.println(F("  <3 <3"));
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
