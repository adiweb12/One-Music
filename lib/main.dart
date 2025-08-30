import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:just_audio/just_audio.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter_equalizer/flutter_equalizer.dart';
import 'package:flutter_audio_waveforms/flutter_audio_waveforms.dart';
import 'package:flutter_media_metadata/flutter_media_metadata.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() => runApp(const ONEUltimateApp());

class ONEUltimateApp extends StatelessWidget {
  const ONEUltimateApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'ONE Ultimate Music Player',
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: Colors.black,
        colorScheme: ColorScheme.dark(primary: Colors.tealAccent),
      ),
      home: const ONEUltimateHomePage(),
    );
  }
}

class ONEUltimateHomePage extends StatefulWidget {
  const ONEUltimateHomePage({super.key});
  @override
  State<ONEUltimateHomePage> createState() => _ONEUltimateHomePageState();
}

class _ONEUltimateHomePageState extends State<ONEUltimateHomePage> with SingleTickerProviderStateMixin {
  final AudioPlayer _player = AudioPlayer();
  final PlayerController _waveController = PlayerController();
  List<String> songs = [];
  Set<String> favorites = {};
  Map<String, Uint8List?> albumArts = {};
  int currentIndex = 0;
  double speed = 1.0;
  bool isPlaying = false;
  List<int> bandLevels = List.filled(5, 0);
  late AnimationController _iconController;

  @override
  void initState() {
    super.initState();
    _iconController = AnimationController(vsync: this, duration: const Duration(milliseconds: 400));
    _player.playerStateStream.listen((state) {
      setState(() {
        isPlaying = state.playing;
        if (isPlaying) _iconController.forward();
        else _iconController.reverse();
      });
    });
    initEqualizer();
    loadPrefs();
  }

  Future<void> loadPrefs() async {
    SharedPreferences prefs = await SharedPreferences.getInstance();
    List<String>? savedSongs = prefs.getStringList('songs');
    List<String>? savedFavs = prefs.getStringList('favorites');
    if (savedSongs != null) {
      songs = savedSongs;
      for (var path in songs) await loadAlbumArt(File(path));
    }
    if (savedFavs != null) favorites = savedFavs.toSet();
    setState(() {});
  }

  Future<void> savePrefs() async {
    SharedPreferences prefs = await SharedPreferences.getInstance();
    await prefs.setStringList('songs', songs);
    await prefs.setStringList('favorites', favorites.toList());
  }

  Future<void> pickSongs() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles(
      allowMultiple: true,
      type: FileType.audio,
    );
    if (result != null) {
      for (var path in result.paths.whereType<String>()) {
        if (!songs.contains(path)) {
          songs.add(path);
          await loadAlbumArt(File(path));
        }
      }
      savePrefs();
      setState(() {});
    }
  }

  Future<void> loadAlbumArt(File file) async {
    MetadataRetriever retriever = MetadataRetriever();
    Metadata? meta = await retriever.fromFile(file);
    albumArts[file.path] = meta?.albumArt;
  }

  Future<void> playSong(int index) async {
    if (songs.isEmpty) return;
    currentIndex = index;
    await _player.stop();
    await _player.setFilePath(songs[currentIndex]);
    await _player.play();
    _waveController.start();
    setState(() {});
  }

  void pause() {
    _player.pause();
    _waveController.pause();
  }

  void stop() {
    _player.stop();
    _waveController.stop();
  }

  void next() => playSong((currentIndex + 1) % songs.length);
  void previous() => playSong((currentIndex - 1 + songs.length) % songs.length);
  void setSpeed(double value) {
    speed = value;
    _player.setSpeed(speed);
    setState(() {});
  }

  Future<void> initEqualizer() async => await FlutterEqualizer.init(0);
  void setBandLevel(int band, int level) => FlutterEqualizer.setBandLevel(band, level);

  void toggleFavorite(String path) {
    if (favorites.contains(path)) favorites.remove(path);
    else favorites.add(path);
    savePrefs();
    setState(() {});
  }

  @override
  void dispose() {
    _player.dispose();
    _waveController.dispose();
    _iconController.dispose();
    super.dispose();
  }

  Uint8List? get currentArt => albumArts[currentSong ?? '']);
  String? get currentSong => songs.isNotEmpty ? songs[currentIndex] : null;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('ONE Ultimate Music Player'),
        actions: [IconButton(icon: const Icon(Icons.add), onPressed: pickSongs)],
      ),
      body: Column(
        children: [
          Expanded(
            child: ListView.builder(
              itemCount: songs.length,
              itemBuilder: (_, index) {
                final song = songs[index];
                bool fav = favorites.contains(song);
                return Dismissible(
                  key: Key(song),
                  background: Container(color: Colors.red, alignment: Alignment.centerLeft, padding: const EdgeInsets.only(left: 20), child: const Icon(Icons.delete, color: Colors.white)),
                  secondaryBackground: Container(color: Colors.green, alignment: Alignment.centerRight, padding: const EdgeInsets.only(right: 20), child: const Icon(Icons.favorite, color: Colors.white)),
                  onDismissed: (direction) {
                    songs.removeAt(index);
                    favorites.remove(song);
                    albumArts.remove(song);
                    if (currentIndex >= songs.length) currentIndex = songs.length - 1;
                    savePrefs();
                    setState(() {});
                  },
                  child: ListTile(
                    leading: currentIndex == index
                        ? const Icon(Icons.play_arrow, color: Colors.tealAccent)
                        : (albumArts[song] != null ? Image.memory(albumArts[song]!, width: 40, height: 40, fit: BoxFit.cover) : const Icon(Icons.music_note, color: Colors.white)),
                    title: Text(song.split('/').last, style: const TextStyle(color: Colors.white)),
                    trailing: IconButton(
                      icon: Icon(fav ? Icons.favorite : Icons.favorite_border, color: Colors.tealAccent),
                      onPressed: () => toggleFavorite(song),
                    ),
                    onTap: () => playSong(index),
                  ),
                );
              },
            ),
          ),
          if (currentSong != null) bottomPlayer(),
        ],
      ),
    );
  }

  Widget bottomPlayer() {
    return Container(
      padding: const EdgeInsets.all(10),
      color: Colors.grey[900],
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Row(
            children: [
              CircleAvatar(
                radius: 30,
                backgroundColor: Colors.grey[800],
                backgroundImage: currentArt != null ? MemoryImage(currentArt!) : null,
                child: currentArt == null ? const Icon(Icons.music_note, color: Colors.white) : null,
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  currentSong!.split('/').last,
                  style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ],
          ),
          const SizedBox(height: 5),
          AudioFileWaveforms(
            size: const Size(double.infinity, 50),
            playerController: _waveController,
            enableSeekGesture: false,
            waveformType: WaveformType.fitWidth,
            waveformData: List.filled(100, 1),
          ),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceAround,
            children: [
              IconButton(icon: const Icon(Icons.skip_previous, color: Colors.tealAccent), onPressed: previous),
              IconButton(
                iconSize: 40,
                icon: AnimatedIcon(icon: AnimatedIcons.play_pause, progress: _iconController, color: Colors.white),
                onPressed: () => isPlaying ? pause() : playSong(currentIndex),
              ),
              IconButton(icon: const Icon(Icons.stop, color: Colors.white), onPressed: stop),
              IconButton(icon: const Icon(Icons.skip_next, color: Colors.tealAccent), onPressed: next),
              IconButton(icon: const Icon(Icons.equalizer, color: Colors.tealAccent), onPressed: () => showDialog(context: context, builder: (_) => equalizerDialog())),
            ],
          ),
          Row(
            children: [
              const Text("Speed", style: TextStyle(color: Colors.white)),
              Expanded(
                child: Slider(
                  value: speed,
                  min: 0.5,
                  max: 2.0,
                  divisions: 6,
                  label: "${speed}x",
                  onChanged: setSpeed,
                  activeColor: Colors.tealAccent,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget equalizerDialog() {
    return AlertDialog(
      title: const Text("Equalizer"),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: List.generate(5, (i) {
          return Column(
            children: [
              Text("Band ${i + 1}", style: const TextStyle(color: Colors.white)),
              Slider(
                value: bandLevels[i].toDouble(),
                min: -10,
                max: 10,
                divisions: 20,
                label: "${bandLevels[i]}",
                onChanged: (v) {
                  setState(() {
                    bandLevels[i] = v.toInt();
                    setBandLevel(i, bandLevels[i]);
                  });
                },
                activeColor: Colors.tealAccent,
              ),
            ],
          );
        }),
      ),
      actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text("Close"))],
      backgroundColor: Colors.grey[900],
    );
  }
}
