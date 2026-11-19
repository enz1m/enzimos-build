/* SPDX-License-Identifier: MIT
 * Explicit Flatpak test client: a persistent bus peer submits an FD, without
 * direct network/CUPS access. This is not a shipping application or UI.
 */
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static GMainLoop *loop;
static gchar *request_path;
static guint response = 99;

static void received(GDBusConnection *connection, const gchar *sender,
                     const gchar *path, const gchar *interface,
                     const gchar *signal, GVariant *parameters, gpointer data)
{
    (void)connection; (void)sender; (void)interface; (void)signal; (void)data;
    if (g_strcmp0(path, request_path) != 0) return;
    GVariant *results = NULL;
    g_variant_get(parameters, "(u@a{sv})", &response, &results);
    g_variant_unref(results);
    g_main_loop_quit(loop);
}

static gboolean deadline(gpointer data)
{
    (void)data;
    g_main_loop_quit(loop);
    return G_SOURCE_REMOVE;
}

int main(int argc, char **argv)
{
    if (argc != 3 || access("/.flatpak-info", R_OK) != 0) return 2;
    if (access("/run/cups/cups.sock", F_OK) == 0) return 2;
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return 2;
    for (struct ifaddrs *entry = interfaces; entry; entry = entry->ifa_next) {
        if (entry->ifa_addr && !(entry->ifa_flags & IFF_LOOPBACK) &&
            (entry->ifa_addr->sa_family == AF_INET || entry->ifa_addr->sa_family == AF_INET6)) {
            freeifaddrs(interfaces);
            return 2;
        }
    }
    freeifaddrs(interfaces);
    puts("ENZIMOS_FLATPAK_NO_DIRECT_CUPS_OR_NETWORK");
    fflush(stdout);
    gboolean cancel = strcmp(argv[1], "cancel") == 0;
    if (!cancel && strcmp(argv[1], "print") != 0) return 2;
    int fd = open(argv[2], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    if (fd < 0 || fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size < 1 || info.st_size > 4 * 1024 * 1024) return 2;
    GError *error = NULL;
    GDBusConnection *connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    if (!connection) return 3;
    gchar *sender = g_strdup(g_dbus_connection_get_unique_name(connection) + 1);
    g_strdelimit(sender, ".", '_');
    gchar *token = g_strdup_printf("enzimos_print_%ld", (long)getpid());
    request_path = g_strdup_printf("/org/freedesktop/portal/desktop/request/%s/%s", sender, token);
    loop = g_main_loop_new(NULL, FALSE);
    guint subscription = g_dbus_connection_signal_subscribe(connection,
        "org.freedesktop.portal.Desktop", "org.freedesktop.portal.Request", "Response",
        NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE, received, NULL, NULL);
    GUnixFDList *fds = g_unix_fd_list_new();
    int handle = g_unix_fd_list_append(fds, fd, &error);
    close(fd);
    if (handle < 0) return 3;
    GVariantBuilder options;
    g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add(&options, "{sv}", "handle_token", g_variant_new_string(token));
    GVariant *reply = g_dbus_connection_call_with_unix_fd_list_sync(connection,
        "org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Print", "Print",
        g_variant_new("(ssh@a{sv})", "", "enzimOS sandbox printing test", handle,
                      g_variant_builder_end(&options)),
        G_VARIANT_TYPE("(o)"), G_DBUS_CALL_FLAGS_NONE, 30000, fds, NULL, NULL, &error);
    if (!reply) {
        fprintf(stderr, "Print portal request failed: %s\n", error->message);
        return 3;
    }
    const gchar *returned;
    g_variant_get(reply, "(&o)", &returned);
    if (g_strcmp0(returned, request_path) != 0) return 3;
    puts("ENZIMOS_FLATPAK_PRINT_DIALOG_READY");
    fflush(stdout);
    guint timeout = g_timeout_add_seconds(180, deadline, NULL);
    g_main_loop_run(loop);
    if (response != 99) g_source_remove(timeout);
    printf("ENZIMOS_FLATPAK_PRINT_RESPONSE %u\n", response);
    g_dbus_connection_signal_unsubscribe(connection, subscription);
    g_variant_unref(reply); g_object_unref(fds); g_object_unref(connection);
    g_main_loop_unref(loop); g_free(sender); g_free(token); g_free(request_path);
    return response == (cancel ? 1U : 0U) ? 0 : 4;
}
