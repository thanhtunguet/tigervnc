/* Copyright 2011-2025 Pierre Ossman <ossman@cendio.se> for Cendio AB
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <dlfcn.h>

#include <set>

#include <FL/Enumerations.H>
#include <FL/Fl_Window.H>
#include <FL/x.H>

#import <Cocoa/Cocoa.h>
#import <ApplicationServices/ApplicationServices.h>

#include "cocoa.h"

static CFMachPortRef event_tap;
static CFRunLoopSourceRef tap_source;

// NSWindows currently animating into or out of native fullscreen.
// toggleFullScreen: called again on a window while it is still
// transitioning will wedge AppKit's fullscreen state machine and
// hang the whole application, so we track this explicitly rather
// than relying on styleMask (which only updates once the animation
// has finished).
static std::set<NSWindow*> fullscreenTransitioning;

static void cocoaTrackFullscreenTransitions(Fl_Window *win, NSWindow *nsw)
{
  // Raw pointers only: once a window is torn down (see the
  // NSWindowWillCloseNotification observer below) we drop it from
  // these sets immediately, so a later NSWindow allocated at the same
  // address (common with allocator reuse across reconnects) is never
  // mistaken for one we're already observing.
  static std::set<NSWindow*> observed;
  if (observed.count(nsw))
    return;
  observed.insert(nsw);

  NSNotificationCenter *center = [NSNotificationCenter defaultCenter];

  // Blocks must not capture nsw strongly: this file is built without
  // ARC, but a block copied for long-term storage (as
  // addObserverForName:usingBlock: does) still retains any captured
  // Objective-C object pointer unless it's qualified unretained. A
  // strong capture here would keep every NSWindow alive forever,
  // leaking one per connection. We never message unsafeNsw, only use
  // it as a set key, so there's no dangling-pointer risk.
  __unsafe_unretained NSWindow *unsafeNsw = nsw;

  void (^begin)(NSNotification*) = ^(NSNotification*) {
    fullscreenTransitioning.insert(unsafeNsw);
  };
  // FLTK has no idea we just entered/left fullscreen behind its back
  // (fullscreen_active() is a plain flag toggled by its own software
  // fullscreen() / fullscreen_off()), so bring it up to date here and
  // replay the FL_FULLSCREEN event it would normally have sent, since
  // the rest of DesktopWindow (keyboard grab, overlay tip, scrollbar
  // layout) keys off of that.
  void (^entered)(NSNotification*) = ^(NSNotification*) {
    fullscreenTransitioning.erase(unsafeNsw);
    win->_set_fullscreen();
    win->handle(FL_FULLSCREEN);
  };
  void (^exited)(NSNotification*) = ^(NSNotification*) {
    fullscreenTransitioning.erase(unsafeNsw);
    win->_clear_fullscreen();
    win->handle(FL_FULLSCREEN);
  };

  [center addObserverForName:NSWindowWillEnterFullScreenNotification
                       object:nsw queue:nil usingBlock:begin];
  [center addObserverForName:NSWindowWillExitFullScreenNotification
                       object:nsw queue:nil usingBlock:begin];
  [center addObserverForName:NSWindowDidEnterFullScreenNotification
                       object:nsw queue:nil usingBlock:entered];
  [center addObserverForName:NSWindowDidExitFullScreenNotification
                       object:nsw queue:nil usingBlock:exited];
  // NSWindowDelegate has windowDidFailToEnter/ExitFullScreen: callbacks,
  // but no equivalent notification-center broadcasts, and we can't
  // become the delegate without clobbering FLTK's own. As a safety net
  // against a failed transition leaving a window stuck forever, clear
  // the flag unconditionally a bit after any transition should have
  // finished (macOS animates this in well under a second).
  void (^safetyClear)(NSNotification*) = ^(NSNotification*) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
      fullscreenTransitioning.erase(unsafeNsw);
    });
  };
  [center addObserverForName:NSWindowWillEnterFullScreenNotification
                       object:nsw queue:nil usingBlock:safetyClear];
  [center addObserverForName:NSWindowWillExitFullScreenNotification
                       object:nsw queue:nil usingBlock:safetyClear];

  [center addObserverForName:NSWindowWillCloseNotification
                       object:nsw queue:nil usingBlock:^(NSNotification*) {
    fullscreenTransitioning.erase(unsafeNsw);
    observed.erase(unsafeNsw);
  }];
}

void cocoa_prevent_native_fullscreen(Fl_Window *win)
{
  NSWindow *nsw;
  nsw = (NSWindow*)fl_xid(win);
  assert(nsw);
#if MAC_OS_X_VERSION_MAX_ALLOWED >= 100700
  nsw.collectionBehavior |= NSWindowCollectionBehaviorFullScreenNone;
#endif
}

void cocoa_enable_native_fullscreen(Fl_Window *win)
{
  NSWindow *nsw;
  nsw = (NSWindow*)fl_xid(win);
  assert(nsw);
#if MAC_OS_X_VERSION_MAX_ALLOWED >= 100700
  nsw.collectionBehavior |= NSWindowCollectionBehaviorFullScreenPrimary;
#endif
}

void cocoa_toggle_native_fullscreen(Fl_Window *win)
{
  NSWindow *nsw;
  nsw = (NSWindow*)fl_xid(win);
  assert(nsw);
#if MAC_OS_X_VERSION_MAX_ALLOWED >= 100700
  // Ensure the window supports native fullscreen
  nsw.collectionBehavior |= NSWindowCollectionBehaviorFullScreenPrimary;

  cocoaTrackFullscreenTransitions(win, nsw);

  // Calling toggleFullScreen: again while a previous transition is
  // still animating confuses AppKit and can hang the application, so
  // ignore repeat requests until the current transition completes.
  if (fullscreenTransitioning.count(nsw))
    return;

  [nsw toggleFullScreen:nil];
#endif
}

bool cocoa_is_native_fullscreen(Fl_Window *win)
{
  NSWindow *nsw;
  nsw = (NSWindow*)fl_xid(win);
  assert(nsw);
#if MAC_OS_X_VERSION_MAX_ALLOWED >= 100700
  return (nsw.styleMask & NSFullScreenWindowMask) != 0;
#else
  return false;
#endif
}

bool cocoa_is_trusted(bool prompt)
{
  CFStringRef keys[1];
  CFBooleanRef values[1];
  CFDictionaryRef options;

  Boolean trusted;

#if !defined(MAC_OS_X_VERSION_10_9) || MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_9
  // FIXME: Raise system requirements so this isn't needed
  void *lib;
  typedef Boolean (*AXIsProcessTrustedWithOptionsRef)(CFDictionaryRef);
  AXIsProcessTrustedWithOptionsRef AXIsProcessTrustedWithOptions;
  CFStringRef kAXTrustedCheckOptionPrompt;

  lib = dlopen(nullptr, 0);
  if (lib == nullptr)
    return false;

  AXIsProcessTrustedWithOptions =
    (AXIsProcessTrustedWithOptionsRef)dlsym(lib, "AXIsProcessTrustedWithOptions");

  dlclose(lib);

  if (AXIsProcessTrustedWithOptions == nullptr)
    return false;

  kAXTrustedCheckOptionPrompt = CFSTR("AXTrustedCheckOptionPrompt");
#endif

  keys[0] = kAXTrustedCheckOptionPrompt;
  values[0] = prompt ? kCFBooleanTrue : kCFBooleanFalse;
  options = CFDictionaryCreate(kCFAllocatorDefault,
                               (const void**)keys,
                               (const void**)values, 1,
                               &kCFCopyStringDictionaryKeyCallBacks,
                               &kCFTypeDictionaryValueCallBacks);
  if (options == nullptr)
    return false;

  trusted = AXIsProcessTrustedWithOptions(options);
  CFRelease(options);

  // For some reason, the authentication popups isn't set as active and
  // is hidden behind our window(s). Try to find it and manually switch
  // to it.
  if (!trusted && prompt) {
    long long pid;

    pid = 0;
    for (int attempt = 0; attempt < 5; attempt++) {
      CFArrayRef windowList;

      windowList = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly,
                                              kCGNullWindowID);
      for (int i = 0; i < CFArrayGetCount(windowList); i++) {
        CFDictionaryRef window;
        CFStringRef owner;
        CFNumberRef cfpid;

        window = (CFDictionaryRef)CFArrayGetValueAtIndex(windowList, i);
        assert(window != nullptr);
        owner = (CFStringRef)CFDictionaryGetValue(window,
                                                  kCGWindowOwnerName);
        if (owner == nullptr)
          continue;

        // FIXME: Unknown how stable this identifier is
        CFStringRef authOwner = CFSTR("universalAccessAuthWarn");
        if (CFStringCompare(owner, authOwner, 0) != kCFCompareEqualTo)
          continue;

        cfpid = (CFNumberRef)CFDictionaryGetValue(window,
                                                  kCGWindowOwnerPID);
        if (cfpid == nullptr)
          continue;

        CFNumberGetValue(cfpid, kCFNumberLongLongType, &pid);
        break;
      }

      CFRelease(windowList);

      if (pid != 0)
        break;

      usleep(100000);
    }

    if (pid != 0) {
      NSRunningApplication* authApp;

      authApp = [NSRunningApplication runningApplicationWithProcessIdentifier:pid];
      if (authApp != nil) {
        // Seems to work fine even without yieldActivationToApplication,
        // or NSApplicationActivateIgnoringOtherApps
        [authApp activateWithOptions:0];
      }
    }
  }

  return trusted;
}

static CGEventRef cocoa_event_tap(CGEventTapProxy /*proxy*/,
                                  CGEventType type, CGEventRef event,
                                  void* /*refcon*/)
{
  ProcessSerialNumber psn;
  OSErr err;

  // We should just be getting these events, but just in case
  if ((type != kCGEventKeyDown) &&
      (type != kCGEventKeyUp) &&
      (type != kCGEventFlagsChanged))
    return event;

  // Redirect the event to us, no matter the original target
  // (note that this will loop if kCGAnnotatedSessionEventTap is used)
  err = GetCurrentProcess(&psn);
  if (err != noErr)
    return event;

  // FIXME: macOS refuses to pass events on with the repeat flag set.
  //        Fortunately, we don't actually care about the flag.
  CGEventSetIntegerValueField(event, kCGKeyboardEventAutorepeat, 0);

  // FIXME: CGEventPostToPid() in macOS 10.11+
  CGEventPostToPSN(&psn, event);

  // Stop delivery to original target
  return nullptr;
}

bool cocoa_tap_keyboard()
{
  CGEventMask mask;

  if (event_tap != nullptr)
    return true;

  if (!cocoa_is_trusted())
    return false;

  mask = CGEventMaskBit(kCGEventKeyDown) |
         CGEventMaskBit(kCGEventKeyUp) |
         CGEventMaskBit(kCGEventFlagsChanged);

  // Cannot be kCGAnnotatedSessionEventTap as window manager intercepts
  // before that (e.g. Ctrl+Up)
  event_tap = CGEventTapCreate(kCGSessionEventTap,
                               kCGHeadInsertEventTap,
                               kCGEventTapOptionDefault,
                               mask, cocoa_event_tap, nullptr);
  if (event_tap == nullptr)
    return false;

  tap_source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault,
                                             event_tap, 0);
  CFRunLoopAddSource(CFRunLoopGetCurrent(), tap_source,
                     kCFRunLoopCommonModes);

  return true;
}

void cocoa_untap_keyboard()
{
  if (event_tap == nullptr)
    return;

  // Need to explicitly disable the tap first, or we get a short delay
  // where all events are dropped
  CGEventTapEnable(event_tap, false);

  CFRunLoopRemoveSource(CFRunLoopGetCurrent(), tap_source,
                        kCFRunLoopCommonModes);
  CFRelease(tap_source);
  tap_source = nullptr;

  CFRelease(event_tap);
  event_tap = nullptr;
}

bool cocoa_screens_have_separate_spaces()
{
  return [NSScreen screensHaveSeparateSpaces];
}

CGColorSpaceRef cocoa_win_color_space(Fl_Window *win)
{
  NSWindow *nsw;
  NSColorSpace *nscs;

  nsw = (NSWindow*)fl_xid(win);
  assert(nsw);

  nscs = [nsw colorSpace];
  if (nscs == nil) {
    // Offscreen, so return standard SRGB color space
    assert(false);
    return CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
  }

  CGColorSpaceRef lut = [nscs CGColorSpace];

  // We want a permanent reference, not an autorelease
  CGColorSpaceRetain(lut);

  return lut;
}

bool cocoa_win_is_zoomed(Fl_Window *win)
{
  NSWindow *nsw;
  nsw = (NSWindow*)fl_xid(win);
  assert(nsw);
  return [nsw isZoomed];
}

void cocoa_win_zoom(Fl_Window *win)
{
  NSWindow *nsw;
  nsw = (NSWindow*)fl_xid(win);
  assert(nsw);
  [nsw zoom:nsw];
}

void cocoa_enable_minimize(Fl_Window *win)
{
  NSWindow *nsw;
  nsw = (NSWindow*)fl_xid(win);
  assert(nsw);
  nsw.styleMask |= NSWindowStyleMaskMiniaturizable;
}
