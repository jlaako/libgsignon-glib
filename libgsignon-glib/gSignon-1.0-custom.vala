namespace Signon {
    [CCode (cheader_filename = "libgsignon-glib/signon-glib.h", free_function = "signon_security_context_list_free")]
    public class SecurityContextList : GLib.List<Signon.SecurityContext> {
        public GLib.Variant build_variant ();
        public SecurityContextList.deconstruct_variant (GLib.Variant variant);
        public SecurityContextList copy ();
        public void free ();
    }

    [CCode (cheader_filename = "libgsignon-glib/signon-glib.h")]
    public class IdentityFilter : GLib.HashTable<string, GLib.Variant> {
        
    }

    [CCode (cheader_filename = "libgsignon-glib/signon-glib.h")]
    public class IdentityList : GLib.List<Signon.Identity> {
        
    }
}
