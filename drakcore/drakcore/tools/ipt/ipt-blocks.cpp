#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <streambuf>
#include <string>
#include <type_traits>
#include <vector>

#include "intel-pt.h"
#include "json-c/json.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/spdlog.h"

#define PTW_CURRENT_CR3 (0xC3000000)
#define PTW_CURRENT_TID (0x1D000000)
#define PTW_EVENT_ID (0xCC000000)
#define PTW_ERROR_EMPTY (0xBAD10000)

#define PTW_CMD_SHIFT 32

bool is_drakvuf_ptwrite(const pt_event *event) {
  if (event->type != ptev_ptwrite) {
    return false;
  }

  uint32_t cmd = event->variant.ptwrite.payload >> PTW_CMD_SHIFT;

  switch (cmd) {
    case PTW_CURRENT_CR3:
    case PTW_CURRENT_TID:
    case PTW_EVENT_ID:
      return true;
  }

  return false;
}

template <typename T>
std::string to_hex(T value) {
  std::stringstream ss;
  ss << "0x" << std::hex << value;
  return ss.str();
}

template <typename T>
void emit_event(const std::string &type, T payload) {
  json_object *root = json_object_new_object();

  json_object_object_add(root, "event", json_object_new_string(type.c_str()));

  if constexpr (std::is_same<T, std::string>::value) {
    json_object_object_add(root, "data",
                           json_object_new_string(payload.c_str()));
  } else if constexpr (std::is_same<T, uint32_t>::value) {
    json_object_object_add(root, "data", json_object_new_int(payload));
  } else {
    // Unsupported type, fail compilation
    static_assert(std::is_same_v<T, void>);
  }

  std::cout << json_object_to_json_string(root) << "\n";

  json_object_put(root);
}

class Image {
 public:
  Image() : cr3_value{0} {
    section_cache_ =
        std::unique_ptr<pt_image_section_cache, ImageSecDeleter>(
            pt_iscache_alloc(nullptr), pt_iscache_free);

    image_ = std::unique_ptr<pt_image, ImageDeleter>(
        pt_image_alloc(nullptr), pt_image_free);
  }

  int map_page(const std::string &fname, uint64_t address) {
    const auto isid = pt_iscache_add_file(section_cache_.get(), fname.c_str(),
                                          0, 0x1000, address);
    if (isid < 0) {
      spdlog::error("Failed to map {} at {:x}", fname, address);
      return -1;
    }
    const auto err =
        pt_image_add_cached(image_.get(), section_cache_.get(), isid, nullptr);
    if (err < 0) {
      spdlog::error("Failed to map {} at {:x}", fname, address);
      return -1;
    }
    return 0;
  }

  pt_image *get_pt_image() const {
    return image_.get();
  }

  uint32_t cr3_value;

 private:
  using ImageSecDeleter = std::function<void(pt_image_section_cache *)>;
  using ImageDeleter = std::function<void(pt_image *)>;

  std::unique_ptr<pt_image_section_cache, ImageSecDeleter>
      section_cache_;
  std::unique_ptr<pt_image, ImageDeleter> image_;
};

class Decoder {
 public:
  Decoder() : mmap_buffer_{nullptr}, mmap_size_{0} { pt_config_init(&config_); }

  void load_pt(const std::string &filename) {
    if (this->enable_mmap_) {
      this->load_pt_mmap(filename);
    } else {
      this->load_pt_vector(filename);
    }
  }

  ~Decoder() {
    if (mmap_buffer_ != nullptr) {
      munmap(mmap_buffer_, mmap_size_);
    }
  }

  void decode_stream(const Image *image) {
    using BlockDecDeleter = std::function<void(pt_block_decoder *)>;
    auto block_dec = std::unique_ptr<pt_block_decoder, BlockDecDeleter>(
        pt_blk_alloc_decoder(&config_), pt_blk_free_decoder);

    pt_blk_set_image(block_dec.get(), image->get_pt_image());

    uint64_t sync = 0;

    auto decoder = block_dec.get();
    for (;;) {
      pt_block block;
      block.ip = 0;
      block.ninsn = 0;

      // Acquire sync
      int status = pt_blk_sync_forward(decoder);
      if (status < 0) {
        if (status == -pte_eos) {
          spdlog::debug("Cannot sync. End of stream");
          break;
        }

        spdlog::debug("Failed to sync forward: {}", status);

        // Check if we've moved forward after last error
        uint64_t new_sync;
        int errcode = pt_blk_get_offset(decoder, &new_sync);
        if (errcode < 0 || (new_sync <= sync)) {
          spdlog::debug("Unable to move forward. {} ", errcode);
          break;
        }
        sync = new_sync;
        continue;
      }

      uint64_t pt_offset = 0;
      pt_blk_get_offset(decoder, &pt_offset);
      spdlog::debug("Processing pending events (offset: {:x})", pt_offset);

      for (;;) {
        if ((status & pts_event_pending) != 0) {
          status = process_events(decoder);
        }
        if ((status & pts_eos) != 0) {
          break;
        }

        if (status < 0) {
          spdlog::debug("Stopping processing. Reason: {}", status);
          break;
        }

        status = pt_blk_next(decoder, &block, sizeof(block));
        if (block.ninsn != 0 && current_cr3_ == image->cr3_value) {
          emit_event("block_executed", to_hex(block.ip));
        }
        if (status < 0) {
          spdlog::debug("Cannot acquire next block");
          break;
        }
      }
    }
  }

  int process_events(pt_block_decoder *decoder) {
    int status;
    do {
      pt_event event;
      status = pt_blk_event(decoder, &event, sizeof(event));
      if (status < 0) {
        return status;
      }
      process_event(&event);
    } while ((status & pts_event_pending) != 0);

    return status;
  }

  void process_event(const pt_event *event) {
    switch (event->type) {
      case ptev_ptwrite:
        if (is_drakvuf_ptwrite(event)) {
          uint32_t cmd = event->variant.ptwrite.payload >> PTW_CMD_SHIFT;
          uint32_t data = event->variant.ptwrite.payload;

          if (cmd == PTW_CURRENT_CR3) {
            current_cr3_ = data;
          }
          if (!show_drakvuf_) {
            break;
          }

          switch (cmd) {
            case PTW_CURRENT_CR3:
              emit_event("drakvuf_cr3", to_hex(data));
              break;
            case PTW_CURRENT_TID:
              emit_event("drakvuf_tid", data);
              break;
            case PTW_EVENT_ID:
              emit_event("drakvuf_event", data);
              break;
            default:
              emit_event("ptwrite", to_hex(event->variant.ptwrite.payload));
          }
        }
        break;
      case ptev_enabled:
      case ptev_disabled:
      case ptev_async_disabled:
      case ptev_async_branch:
      case ptev_paging:
      case ptev_async_paging:
      case ptev_overflow:
      case ptev_exec_mode:
      case ptev_tsx:
      case ptev_stop:
      case ptev_vmcs:
      case ptev_async_vmcs:
      case ptev_exstop:
      case ptev_mwait:
      case ptev_pwre:
      case ptev_pwrx:
      case ptev_mnt:
      case ptev_tick:
      case ptev_cbr:
        break;
    }
  }

 private:
  void load_pt_mmap(const std::string &filename) {
    if (mmap_buffer_ != nullptr) {
      throw std::runtime_error("Trace alread mmaped");
    }

    int fd = open(filename.c_str(), O_CLOEXEC | O_RDONLY);
    if (fd < 0) {
      throw std::runtime_error("Cannot open " + filename);
    }

    stat file_stat;
    int err = fstat(fd, &file_stat);
    if (err < 0) {
      throw std::runtime_error("Cannot stat PT file");
    }

    mmap_size_ = file_stat.st_size;

    void *ptr = mmap(0, mmap_size_, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED) {
      throw std::runtime_error("Failed to mmap trace file");
    }

    mmap_buffer_ = ptr;
    close(fd);

    config_.begin = static_cast<uint8_t *>(ptr);
    config_.end = static_cast<uint8_t *>(ptr) + mmap_size_;
  }

  void load_pt_vector(const std::string &filename) {
    std::ifstream stream{filename, std::ios::binary};

    stream.seekg(0, std::ios::end);
    proc_trace_.reserve(stream.tellg());
    stream.seekg(0, std::ios::beg);

    proc_trace_.assign(std::istreambuf_iterator<char>{stream},
                       std::istreambuf_iterator<char>{});

    config_.begin = proc_trace_.data();
    config_.end = config_.begin + proc_trace_.size();
  }

 public:
  bool show_drakvuf_ = false;
  bool enable_mmap_ = true;

 private:
  pt_config config_;

  void *mmap_buffer_;
  size_t mmap_size_;
  std::vector<uint8_t> proc_trace_;

  uint32_t current_cr3_;
};

int main(int argc, char *argv[]) {
  auto err_console = spdlog::stderr_color_st("console");
  spdlog::set_default_logger(err_console);

  Decoder decoder{};
  Image image{};

  std::optional<std::string> pt_file;
  std::optional<uint64_t> cr3_filter;

  for (int i = 1; i < argc; i++) {
    const auto arg = std::string(argv[i]);
    const bool has_more_args = i + 1 < argc;
    if (arg == "--pt") {
      if (!has_more_args) {
        std::cerr << "Missing argument for --pt\n";
        return 1;
      }
      i++;
      pt_file = std::string(argv[i]);
    } else if (arg == "--cr3") {
      if (!has_more_args) {
        std::cerr << "Missing argument for --cr3\n";
        return 1;
      }
      i++;
      cr3_filter = std::stoul(std::string(argv[i]), 0, 0);
    } else if (arg == "--raw") {
      if (!has_more_args) {
        std::cerr << "Missing argument for --raw\n";
        return 1;
      }
      i++;
      const auto arg = std::string(argv[i]);
      const auto fname = arg.substr(0, arg.find_first_of(":"));
      const auto addr = arg.substr(arg.find_first_of(":") + 1);
      const uint64_t virt_addr = std::stoull(addr, 0, 0);

      spdlog::debug("Mapping {} at {:x}", fname, virt_addr);
      if (image.map_page(fname, virt_addr) != 0) {
        return 1;
      }
    } else if (arg == "--show-drakvuf") {
      decoder.show_drakvuf_ = true;
    } else if (arg == "--no-mmap") {
      decoder.enable_mmap_ = false;
    } else if (arg == "--verbose") {
      spdlog::set_level(spdlog::level::debug);
    } else {
      std::cerr << "Unknown argument " << arg << "\n";
      return 1;
    }
  }

  if (!pt_file) {
    std::cerr << "Missing --pt [ipt_trace_file]\n";
    return 1;
  }
  if (!cr3_filter) {
    std::cerr << "Missing --cr3 [cr3_filter]\n";
    return 1;
  }

  try {
    decoder.load_pt(*pt_file);
    image.cr3_value = *cr3_filter;
    spdlog::info("Decoding");
    decoder.decode_stream(&image);
  } catch (const std::runtime_error &exc) {
    spdlog::error(exc.what());
    return 1;
  }
}
