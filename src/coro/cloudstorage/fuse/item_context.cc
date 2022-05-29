#include "coro/cloudstorage/fuse/item_context.h"

namespace coro::cloudstorage::fuse {

Task<> ItemContext::NewFileRead::operator()() {
  auto generator =
      provider->GetFileContent(item, http::Range{}, std::move(stop_token));
  FOR_CO_AWAIT(std::string & chunk, std::move(generator)) {
    if (co_await thread_pool->Do(fwrite, chunk.data(), 1, chunk.size(), file) !=
        chunk.size()) {
      throw CloudException("write fail");
    }
  }
}

auto ItemContext::GetId() const -> std::string {
  if (!item_) {
    return "";
  }
  return std::visit([](const auto& d) { return d.id; }, *item_);
}

auto ItemContext::GetTimestamp() const -> std::optional<int64_t> {
  if (!item_) {
    return std::nullopt;
  }
  return std::visit([](const auto& d) { return d.timestamp; }, *item_);
}

auto ItemContext::GetSize() const -> std::optional<int64_t> {
  if (!item_) {
    return std::nullopt;
  }
  return std::visit([](const auto& d) { return d.size; }, *item_);
}

auto ItemContext::GetType() const -> ItemType {
  if (!item_) {
    return ItemType::kFile;
  }
  return std::holds_alternative<Directory>(*item_) ? ItemType::kDirectory
                                                   : ItemType::kFile;
}

std::string ItemContext::GetName() const {
  if (!item_) {
    return "";
  }
  return std::visit([](const auto& d) { return d.name; }, *item_);
}

std::optional<std::string> ItemContext::GetMimeType() const {
  if (!item_ || std::holds_alternative<Directory>(*item_)) {
    return std::nullopt;
  }
  return std::get<File>(*item_).mime_type;
}

}  // namespace coro::cloudstorage::fuse