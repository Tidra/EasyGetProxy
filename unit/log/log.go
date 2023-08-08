package log

import (
	"os"
	"time"

	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type fileSyncer struct {
	*lumberjack.Logger
}

var (
	logger             *zap.Logger
	logFilePath        = "log/run.log"
	fileAtomicLevel    = zap.NewAtomicLevel()
	consoleAtomicLevel = zap.NewAtomicLevel()
	levelMap           = map[string]zapcore.Level{
		"debug": zapcore.DebugLevel,
		"info":  zapcore.InfoLevel,
		"warn":  zapcore.WarnLevel,
		"error": zapcore.ErrorLevel,
	}
	fileDebugging = &fileSyncer{
		Logger: &lumberjack.Logger{
			Filename:   logFilePath,
			MaxSize:    500, // megabytes
			MaxBackups: 3,
			MaxAge:     28, //days
		},
	}
)

func init() {
	// 自定义时间输出格式
	customTimeEncoder := func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString("[" + t.Format("2006-01-02 15:04:05.000") + "]")
	}
	// 自定义日志级别显示
	customLevelEncoder := func(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString("[" + level.CapitalString() + "]")
	}

	// 自定义文件：行号输出项
	customCallerEncoder := func(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString("[" + caller.TrimmedPath() + "]")
	}

	encoderConf := zapcore.EncoderConfig{
		CallerKey:      "caller_line", // 打印文件名和行数
		LevelKey:       "level_name",
		MessageKey:     "msg",
		TimeKey:        "ts",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeTime:     customTimeEncoder,   // 自定义时间格式
		EncodeLevel:    customLevelEncoder,  // 小写编码器
		EncodeCaller:   customCallerEncoder, // 全路径编码器
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeName:     zapcore.FullNameEncoder,
	}

	consoleEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileEncoder := zapcore.NewConsoleEncoder(encoderConf)

	consoleDebugging := zapcore.Lock(os.Stdout)

	consoleAtomicLevel.SetLevel(zap.InfoLevel)
	fileAtomicLevel.SetLevel(zap.InfoLevel)
	consoleCore := zapcore.NewCore(consoleEncoder, consoleDebugging, consoleAtomicLevel)
	fileCore := zapcore.NewCore(fileEncoder, fileDebugging, fileAtomicLevel)

	core := zapcore.NewTee(consoleCore, fileCore)
	logger = zap.New(core, zap.AddCallerSkip(1), zap.AddCaller())

	defer logger.Sync()
}

func (f *fileSyncer) Write(p []byte) (n int, err error) {
	return f.Logger.Write(p)
}

func (f *fileSyncer) Sync() error {
	return nil
}

func SetLogFilePath(file string) {
	fileDebugging.Filename = file
	fileDebugging.Rotate() //触发切割
}

func StringToLevel(levelStr string) zapcore.Level {
	if level, ok := levelMap[levelStr]; ok {
		return level
	}
	return zapcore.FatalLevel // 默认Fatal级别
}

func SetLogLevel(fileLevel string, consoleLevel string) {
	fileAtomicLevel.SetLevel(StringToLevel(fileLevel))
	consoleAtomicLevel.SetLevel(StringToLevel(consoleLevel))
}

func LogDebug(msg string, args ...interface{}) {
	logger.Sugar().Debugf(msg, args...)
}
func LogInfo(msg string, args ...interface{}) {
	logger.Sugar().Infof(msg, args...)
}

func LogWarn(msg string, args ...interface{}) {
	logger.Sugar().Warnf(msg, args...)
}

func LogError(msg string, args ...interface{}) {
	logger.Sugar().Errorf(msg, args...)
}
