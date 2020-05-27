/***********************************************************************
 * Name: get ANDROID_ID
 * OS: Android
 * Author: iddoeldor
 * Source: https://github.com/iddoeldor/frida-snippets#get-android-id
 * Info: The ANDROID_ID is unique in each application 
 ***********************************************************************/

Java.perform(function () {
  function getContext() {
      return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver();
  }
  send('[-]' + Java.use('android.provider.Settings$Secure').getString(getContext(), 'android_id'));
});