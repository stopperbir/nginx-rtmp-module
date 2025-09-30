#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_codec_module.h>
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_mp4.h"

static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;

static ngx_int_t ngx_rtmp_dash_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_dash_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_dash_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static ngx_int_t ngx_rtmp_dash_write_init_segments(ngx_rtmp_session_t *s);

#define NGX_RTMP_DASH_BUFSIZE           (1024*1024)
#define NGX_RTMP_DASH_MAX_MDAT          (10*1024*1024)
#define NGX_RTMP_DASH_MAX_SAMPLES       1024
#define NGX_RTMP_DASH_DIR_ACCESS        0744

typedef struct {
    uint32_t                            timestamp;
    uint32_t                            duration;
} ngx_rtmp_dash_frag_t;

typedef struct {
    ngx_uint_t                          id;
    ngx_uint_t                          opened;
    ngx_uint_t                          mdat_size;
    ngx_uint_t                          sample_count;
    ngx_uint_t                          sample_mask;
    ngx_fd_t                            fd;
    char                                type;
    uint32_t                            earliest_pres_time;
    uint32_t                            latest_pres_time;
    ngx_rtmp_mp4_sample_t               samples[NGX_RTMP_DASH_MAX_SAMPLES];
} ngx_rtmp_dash_track_t;

typedef struct {
    ngx_str_t                           playlist;
    ngx_str_t                           playlist_bak;
    ngx_str_t                           name;
    ngx_str_t                           stream;
    time_t                              start_time;

    ngx_uint_t                          nfrags;
    ngx_uint_t                          frag;
    ngx_rtmp_dash_frag_t               *frags;

    unsigned                            opened:1;
    unsigned                            has_video:1;
    unsigned                            has_audio:1;

    ngx_file_t                          video_file;
    ngx_file_t                          audio_file;

    ngx_uint_t                          id;

    ngx_rtmp_dash_track_t               audio;
    ngx_rtmp_dash_track_t               video;
} ngx_rtmp_dash_ctx_t;

/* --- Manifest Macros with Modified Extensions --- */

#define NGX_RTMP_DASH_MANIFEST_VIDEO                                           \
    "    <AdaptationSet\n"                                                     \
    "        id=\"1\"\n"                                                       \
    "        segmentAlignment=\"true\"\n"                                      \
    "        maxWidth=\"%ui\"\n"                                               \
    "        maxHeight=\"%ui\"\n"                                              \
    "        maxFrameRate=\"%ui\">\n"                                          \
    "      <Representation\n"                                                  \
    "          id=\"%V_H264\"\n"                                               \
    "          mimeType=\"image/jpeg\"\n"                                      \
    "          codecs=\"avc1.%02uxi%02uxi%02uxi\"\n"                           \
    "          width=\"%ui\"\n"                                                \
    "          height=\"%ui\"\n"                                               \
    "          frameRate=\"%ui\"\n"                                            \
    "          startWithSAP=\"1\"\n"                                           \
    "          bandwidth=\"%ui\">\n"                                           \
    "        <SegmentTemplate\n"                                               \
    "            timescale=\"1000\"\n"                                         \
    "            media=\"%V%s$Time$.jpg\"\n"                                   \
    "            initialization=\"%V%sinit.jpg\">\n"                           \
    "          <SegmentTimeline>\n"

#define NGX_RTMP_DASH_MANIFEST_AUDIO                                           \
    "    <AdaptationSet\n"                                                     \
    "        id=\"2\"\n"                                                       \
    "        segmentAlignment=\"true\">\n"                                     \
    "      <AudioChannelConfiguration\n"                                       \
    "          schemeIdUri=\"urn:mpeg:dash:"                                   \
                                "23003:3:audio_channel_configuration:2011\"\n" \
    "          value=\"1\"/>\n"                                                \
    "      <Representation\n"                                                  \
    "          id=\"%V_AAC\"\n"                                                \
    "          mimeType=\"text/css\"\n"                                        \
    "          codecs=\"mp4a.%s\"\n"                                           \
    "          audioSamplingRate=\"%ui\"\n"                                    \
    "          startWithSAP=\"1\"\n"                                           \
    "          bandwidth=\"%ui\">\n"                                           \
    "        <SegmentTemplate\n"                                               \
    "            timescale=\"1000\"\n"                                         \
    "            media=\"%V%s$Time$.css\"\n"                                   \
    "            initialization=\"%V%sinit.css\">\n"                           \
    "          <SegmentTimeline>\n"
static ngx_int_t
ngx_rtmp_dash_write_init_segments(ngx_rtmp_session_t *s)
{
    ngx_fd_t               fd;
    ngx_int_t              rc;
    ngx_buf_t              b;
    ngx_rtmp_dash_ctx_t   *ctx;
    ngx_rtmp_codec_ctx_t  *codec_ctx;

    static u_char          buffer[NGX_RTMP_DASH_BUFSIZE];

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (ctx == NULL || codec_ctx == NULL) {
        return NGX_ERROR;
    }

    /* init video → init.jpg */
    *ngx_sprintf(ctx->stream.data + ctx->stream.len, "init.jpg") = 0;

    fd = ngx_open_file(ctx->stream.data, NGX_FILE_RDWR, NGX_FILE_TRUNCATE,
                       NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: error creating video init file");
        return NGX_ERROR;
    }

    b.start = buffer;
    b.end = b.start + sizeof(buffer);
    b.pos = b.last = b.start;

    ngx_rtmp_mp4_write_ftyp(&b);
    ngx_rtmp_mp4_write_moov(s, &b, NGX_RTMP_MP4_VIDEO_TRACK);

    rc = ngx_write_fd(fd, b.start, (size_t) (b.last - b.start));
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: writing video init failed");
    }

    ngx_close_file(fd);

    /* init audio → init.css */
    *ngx_sprintf(ctx->stream.data + ctx->stream.len, "init.css") = 0;

    fd = ngx_open_file(ctx->stream.data, NGX_FILE_RDWR, NGX_FILE_TRUNCATE,
                       NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: error creating dash audio init file");
        return NGX_ERROR;
    }

    b.pos = b.last = b.start;

    ngx_rtmp_mp4_write_ftyp(&b);
    ngx_rtmp_mp4_write_moov(s, &b, NGX_RTMP_MP4_AUDIO_TRACK);

    rc = ngx_write_fd(fd, b.start, (size_t) (b.last - b.start));
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: writing audio init failed");
    }

    ngx_close_file(fd);

    return NGX_OK;
}

/* --- Fragment close: .jpg ve .css --- */

static void
ngx_rtmp_dash_close_fragment(ngx_rtmp_session_t *s, ngx_rtmp_dash_track_t *t)
{
    u_char                    *pos, *pos1;
    size_t                     left;
    ssize_t                    n;
    ngx_fd_t                   fd;
    ngx_buf_t                  b;
    ngx_rtmp_dash_ctx_t       *ctx;
    ngx_rtmp_dash_frag_t      *f;

    static u_char              buffer[NGX_RTMP_DASH_BUFSIZE];

    if (!t->opened) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);

    b.start = buffer;
    b.end = buffer + sizeof(buffer);
    b.pos = b.last = b.start;

    ngx_rtmp_mp4_write_styp(&b);

    pos = b.last;
    b.last += 44;

    ngx_rtmp_mp4_write_moof(&b, t->earliest_pres_time, t->sample_count,
                            t->samples, t->sample_mask, t->id);
    pos1 = b.last;
    b.last = pos;

    ngx_rtmp_mp4_write_sidx(&b, t->mdat_size + 8 + (pos1 - (pos + 44)),
                            t->earliest_pres_time, t->latest_pres_time);
    b.last = pos1;
    ngx_rtmp_mp4_write_mdat(&b, t->mdat_size + 8);

    f = ngx_rtmp_dash_get_frag(s, ctx->nfrags);

    if (t->type == 'v') {
        *ngx_sprintf(ctx->stream.data + ctx->stream.len, "%uD.jpg",
                     f->timestamp) = 0;
    } else {
        *ngx_sprintf(ctx->stream.data + ctx->stream.len, "%uD.css",
                     f->timestamp) = 0;
    }

    fd = ngx_open_file(ctx->stream.data, NGX_FILE_RDWR,
                       NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "dash: error creating dash fragment file");
        goto done;
    }

    if (ngx_write_fd(fd, b.pos, (size_t) (b.last - b.pos)) == NGX_ERROR) {
        goto done;
    }

    left = (size_t) t->mdat_size;

#if (NGX_WIN32)
    if (SetFilePointer(t->fd, 0, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        goto done;
    }
#else
    if (lseek(t->fd, 0, SEEK_SET) == -1) {
        goto done;
    }
#endif

    while (left > 0) {
        n = ngx_read_fd(t->fd, buffer, ngx_min(sizeof(buffer), left));
        if (n == NGX_ERROR) {
            break;
        }

        n = ngx_write_fd(fd, buffer, (size_t) n);
        if (n == NGX_ERROR) {
            break;
        }

        left -= n;
    }

done:
    if (fd != NGX_INVALID_FILE) {
        ngx_close_file(fd);
    }
    ngx_close_file(t->fd);

    t->fd = NGX_INVALID_FILE;
    t->opened = 0;
}
static ngx_int_t
ngx_rtmp_dash_open_fragment(ngx_rtmp_session_t *s, ngx_rtmp_dash_track_t *t,
    ngx_uint_t id, char type)
{
    ngx_rtmp_dash_ctx_t   *ctx;

    if (t->opened) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);

    if (type == 'v') {
        *ngx_sprintf(ctx->stream.data + ctx->stream.len, "raw.jpg") = 0;
    } else {
        *ngx_sprintf(ctx->stream.data + ctx->stream.len, "raw.css") = 0;
    }

    t->fd = ngx_open_file(ctx->stream.data, NGX_FILE_RDWR,
                          NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (t->fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    t->id = id;
    t->type = type;
    t->sample_count = 0;
    t->earliest_pres_time = 0;
    t->latest_pres_time = 0;
    t->mdat_size = 0;
    t->opened = 1;

    if (type == 'v') {
        t->sample_mask = NGX_RTMP_MP4_SAMPLE_SIZE|
                         NGX_RTMP_MP4_SAMPLE_DURATION|
                         NGX_RTMP_MP4_SAMPLE_DELAY|
                         NGX_RTMP_MP4_SAMPLE_KEY;
    } else {
        t->sample_mask = NGX_RTMP_MP4_SAMPLE_SIZE|
                         NGX_RTMP_MP4_SAMPLE_DURATION;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_dash_open_fragments(ngx_rtmp_session_t *s)
{
    ngx_rtmp_dash_ctx_t  *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);

    if (ctx->opened) {
        return NGX_OK;
    }

    ngx_rtmp_dash_open_fragment(s, &ctx->video, ctx->id, 'v');
    ngx_rtmp_dash_open_fragment(s, &ctx->audio, ctx->id, 'a');

    ctx->opened = 1;
    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_dash_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    u_char                    *p;
    size_t                     len;
    ngx_rtmp_dash_ctx_t       *ctx;
    ngx_rtmp_dash_frag_t      *f;
    ngx_rtmp_dash_app_conf_t  *dacf;

    dacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_dash_module);
    if (dacf == NULL || !dacf->dash || dacf->path.len == 0) {
        goto next;
    }

    if (s->auto_pushed) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_dash_ctx_t));
        if (ctx == NULL) {
            goto next;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_dash_module);
    } else {
        if (ctx->opened) {
            goto next;
        }
        f = ctx->frags;
        ngx_memzero(ctx, sizeof(ngx_rtmp_dash_ctx_t));
        ctx->frags = f;
    }

    if (ctx->frags == NULL) {
        ctx->frags = ngx_pcalloc(s->connection->pool,
                                 sizeof(ngx_rtmp_dash_frag_t) *
                                 (dacf->winfrags * 2 + 1));
        if (ctx->frags == NULL) {
            return NGX_ERROR;
        }
    }

    ctx->id = 0;

    ctx->name.len = ngx_strlen(v->name);
    ctx->name.data = ngx_palloc(s->connection->pool, ctx->name.len + 1);
    if (ctx->name.data == NULL) {
        return NGX_ERROR;
    }
    *ngx_cpymem(ctx->name.data, v->name, ctx->name.len) = 0;

    len = dacf->path.len + 1 + ctx->name.len + sizeof(".mpd");
    if (dacf->nested) {
        len += sizeof("/index") - 1;
    }

    ctx->playlist.data = ngx_palloc(s->connection->pool, len);
    p = ngx_cpymem(ctx->playlist.data, dacf->path.data, dacf->path.len);

    if (p[-1] != '/') {
        *p++ = '/';
    }
    p = ngx_cpymem(p, ctx->name.data, ctx->name.len);

    ctx->stream.len = p - ctx->playlist.data + 1;
    ctx->stream.data = ngx_palloc(s->connection->pool,
                                  ctx->stream.len + NGX_INT32_LEN +
                                  sizeof(".jpg"));
    ngx_memcpy(ctx->stream.data, ctx->playlist.data, ctx->stream.len - 1);
    ctx->stream.data[ctx->stream.len - 1] = (dacf->nested ? '/' : '-');

    if (dacf->nested) {
        p = ngx_cpymem(p, "/index.mpd", sizeof("/index.mpd") - 1);
    } else {
        p = ngx_cpymem(p, ".mpd", sizeof(".mpd") - 1);
    }
    ctx->playlist.len = p - ctx->playlist.data;
    *p = 0;

    /* playlist bak */
    ctx->playlist_bak.data = ngx_palloc(s->connection->pool,
                                        ctx->playlist.len + sizeof(".bak"));
    p = ngx_cpymem(ctx->playlist_bak.data, ctx->playlist.data,
                   ctx->playlist.len);
    p = ngx_cpymem(p, ".bak", sizeof(".bak") - 1);
    ctx->playlist_bak.len = p - ctx->playlist_bak.data;
    *p = 0;

    ctx->start_time = ngx_time();

    if (ngx_rtmp_dash_ensure_directory(s) != NGX_OK) {
        return NGX_ERROR;
    }

next:
    return next_publish(s, v);
}

static ngx_int_t
ngx_rtmp_dash_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_dash_ctx_t       *ctx;
    ngx_rtmp_dash_app_conf_t  *dacf;

    dacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_dash_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);

    if (dacf == NULL || !dacf->dash || ctx == NULL) {
        goto next;
    }

    ngx_rtmp_dash_close_fragments(s);

next:
    return next_close_stream(s, v);
}

static ngx_int_t
ngx_rtmp_dash_append(ngx_rtmp_session_t *s, ngx_chain_t *in,
    ngx_rtmp_dash_track_t *t, ngx_int_t key, uint32_t timestamp, uint32_t delay)
{
    u_char                 *p;
    size_t                  size, bsize;
    ngx_rtmp_mp4_sample_t  *smpl;

    static u_char           buffer[NGX_RTMP_DASH_BUFSIZE];

    p = buffer;
    size = 0;

    for (; in && size < sizeof(buffer); in = in->next) {
        bsize = (size_t) (in->buf->last - in->buf->pos);
        if (size + bsize > sizeof(buffer)) {
            bsize = (size_t) (sizeof(buffer) - size);
        }
        p = ngx_cpymem(p, in->buf->pos, bsize);
        size += bsize;
    }

    ngx_rtmp_dash_update_fragments(s, key, timestamp);

    if (t->sample_count == 0) {
        t->earliest_pres_time = timestamp;
    }
    t->latest_pres_time = timestamp;

    if (t->sample_count < NGX_RTMP_DASH_MAX_SAMPLES) {
        if (ngx_write_fd(t->fd, buffer, size) == NGX_ERROR) {
            return NGX_ERROR;
        }

        smpl = &t->samples[t->sample_count];
        smpl->delay = delay;
        smpl->size = (uint32_t) size;
        smpl->duration = 0;
        smpl->timestamp = timestamp;
        smpl->key = (key ? 1 : 0);

        if (t->sample_count > 0) {
            smpl = &t->samples[t->sample_count - 1];
            smpl->duration = timestamp - smpl->timestamp;
        }

        t->sample_count++;
        t->mdat_size += (ngx_uint_t) size;
    }

    return NGX_OK;
}
static ngx_int_t
ngx_rtmp_dash_audio(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    u_char                     htype;
    ngx_rtmp_dash_ctx_t       *ctx;
    ngx_rtmp_codec_ctx_t      *codec_ctx;
    ngx_rtmp_dash_app_conf_t  *dacf;

    dacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_dash_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (dacf == NULL || !dacf->dash || ctx == NULL ||
        codec_ctx == NULL || h->mlen < 2)
    {
        return NGX_OK;
    }

    if (codec_ctx->audio_codec_id != NGX_RTMP_AUDIO_AAC ||
        codec_ctx->aac_header == NULL)
    {
        return NGX_OK;
    }

    if (in->buf->last - in->buf->pos < 2) {
        return NGX_ERROR;
    }

    htype = in->buf->pos[1];
    if (htype != 1) {
        return NGX_OK;
    }

    ctx->has_audio = 1;
    in->buf->pos += 2;

    return ngx_rtmp_dash_append(s, in, &ctx->audio, 0, h->timestamp, 0);
}

static ngx_int_t
ngx_rtmp_dash_video(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    u_char                    *p;
    uint8_t                    ftype, htype;
    uint32_t                   delay;
    ngx_rtmp_dash_ctx_t       *ctx;
    ngx_rtmp_codec_ctx_t      *codec_ctx;
    ngx_rtmp_dash_app_conf_t  *dacf;

    dacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_dash_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_dash_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (dacf == NULL || !dacf->dash || ctx == NULL || codec_ctx == NULL ||
        codec_ctx->avc_header == NULL || h->mlen < 5)
    {
        return NGX_OK;
    }

    if (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264) {
        return NGX_OK;
    }

    if (in->buf->last - in->buf->pos < 5) {
        return NGX_ERROR;
    }

    ftype = (in->buf->pos[0] & 0xf0) >> 4;
    htype = in->buf->pos[1];
    if (htype != 1) {
        return NGX_OK;
    }

    p = (u_char *) &delay;
    p[0] = in->buf->pos[4];
    p[1] = in->buf->pos[3];
    p[2] = in->buf->pos[2];
    p[3] = 0;

    ctx->has_video = 1;
    in->buf->pos += 5;

    return ngx_rtmp_dash_append(s, in, &ctx->video, ftype == 1, h->timestamp,
                                delay);
}

static ngx_int_t
ngx_rtmp_dash_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    return next_stream_begin(s, v);
}

static ngx_int_t
ngx_rtmp_dash_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_dash_close_fragments(s);
    return next_stream_eof(s, v);
}

/* cleanup kodları aynı kalıyor — sadece .jpg / .css dosyalarını da siler */

static void *
ngx_rtmp_dash_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_dash_app_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_dash_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->dash = NGX_CONF_UNSET;
    conf->fraglen = NGX_CONF_UNSET_MSEC;
    conf->playlen = NGX_CONF_UNSET_MSEC;
    conf->cleanup = NGX_CONF_UNSET;
    conf->nested = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_rtmp_dash_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_dash_app_conf_t    *prev = parent;
    ngx_rtmp_dash_app_conf_t    *conf = child;
    ngx_rtmp_dash_cleanup_t     *cleanup;

    ngx_conf_merge_value(conf->dash, prev->dash, 0);
    ngx_conf_merge_msec_value(conf->fraglen, prev->fraglen, 5000);
    ngx_conf_merge_msec_value(conf->playlen, prev->playlen, 30000);
    ngx_conf_merge_value(conf->cleanup, prev->cleanup, 1);
    ngx_conf_merge_value(conf->nested, prev->nested, 0);

    if (conf->fraglen) {
        conf->winfrags = conf->playlen / conf->fraglen;
    }

    if (conf->dash && conf->path.len && conf->cleanup) {
        if (conf->path.data[conf->path.len - 1] == '/') {
            conf->path.len--;
        }

        cleanup = ngx_pcalloc(cf->pool, sizeof(*cleanup));
        if (cleanup == NULL) {
            return NGX_CONF_ERROR;
        }

        cleanup->path = conf->path;
        cleanup->playlen = conf->playlen;

        conf->slot = ngx_pcalloc(cf->pool, sizeof(*conf->slot));
        if (conf->slot == NULL) {
            return NGX_CONF_ERROR;
        }

        conf->slot->manager = ngx_rtmp_dash_cleanup;
        conf->slot->name = conf->path;
        conf->slot->data = cleanup;
        conf->slot->conf_file = cf->conf_file->file.name.data;
        conf->slot->line = cf->conf_file->line;

        if (ngx_add_path(cf, &conf->slot) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_merge_str_value(conf->path, prev->path, "");
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_rtmp_dash_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_handler_pt        *h;
    ngx_rtmp_core_main_conf_t  *cmcf;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_dash_video;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_dash_audio;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_dash_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_dash_close_stream;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_dash_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_dash_stream_eof;

    return NGX_OK;
}

ngx_module_t  ngx_rtmp_dash_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_dash_module_ctx,          /* module context */
    ngx_rtmp_dash_commands,             /* module directives */
    NGX_RTMP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};
