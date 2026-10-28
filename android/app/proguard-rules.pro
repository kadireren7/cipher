# JNA + UniFFI bindings are reflected by name.
-keep class com.sun.jna.** { *; }
-keep class uniffi.** { *; }
-keepclassmembers class * extends com.sun.jna.* { public *; }
# Embedded Tor (Guardian Project JNI + control library): native methods are looked up by name from libtor.so.
-keep class org.torproject.jni.** { *; }
-keep class net.freehaven.tor.control.** { *; }
-dontwarn java.awt.*
-dontwarn com.sun.jna.**
# Keep line numbers out of release crash traces: no crash reporter is shipped, and stack traces must not leak into logs.
-dontnote **

# Release builds contain NO logging calls at all (SafeLog is the only logger and it only emits closed event codes; this removes even those).
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
    public static boolean isLoggable(...);
}
