using Hebron;
using Hebron.Roslyn;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace cgltf.NET.Generator
{
    internal class Program
    {
        /// <summary>
        /// 把各项枚举，结构，类，方法等集中为一个字符串。
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="input"></param>
        /// <param name="output"></param>
        private static void Write<T>(Dictionary<string, T> input, StringBuilder output) where T : SyntaxNode
        {
            var keys = (from string k in input.Keys select k).ToArray();
            foreach (var key in keys)
            {
                string value;
                using (var sw = new StringWriter())
                {
                    input[key].NormalizeWhitespace().WriteTo(sw);

                    value = sw.ToString();
                    value += Environment.NewLine;
                }

                output.Append(value);
            }
        }

        private static StringBuilder PostProcess(StringBuilder data, bool is_write = false)
        {
            /*
             * 处理delegate在结构中的警告, 采用chatgpt建议，使用IntPtr存储在结构中，使用Marshal.GetFunctionPointerForDelegate和Marshal.GetDelegateForFunctionPointer进行转换
             */
            var delegateLine = "public delegate ";
            data.Replace(delegateLine, "[UnmanagedFunctionPointer(CallingConvention.Cdecl)]" + '\n' + delegateLine);

            data.Replace("public delegate0 alloc_func", "public IntPtr alloc_func");
            data.Replace("public delegate1 free_func", "public IntPtr free_func");
            var addTo_cgltf_memory_options = @$"
        // 设置函数指针的方法
        public void SetAllocFunc(delegate0 allocFunc)
        {{
            alloc_func = Marshal.GetFunctionPointerForDelegate(allocFunc);
        }}

        public void SetFreeFunc(delegate1 freeFunc)
        {{
            free_func = Marshal.GetFunctionPointerForDelegate(freeFunc);
        }}

        // 调用函数指针
        public delegate0 GetAllocFunc()
        {{
            return Marshal.GetDelegateForFunctionPointer<delegate0>(alloc_func);
        }}

        public delegate1 GetFreeFunc()
        {{
            return Marshal.GetDelegateForFunctionPointer<delegate1>(free_func);
        }}";
            var cgltf_memory_options = @$"struct cgltf_memory_options
{{";
            data.Replace(cgltf_memory_options, cgltf_memory_options + addTo_cgltf_memory_options);

            data.Replace("public delegate2 read", "public IntPtr read");
            data.Replace("public delegate3 release", "public IntPtr release");

            var addTo_cgltf_file_options = @$"
        // 设置函数指针的方法
        public void SetRead(delegate2 read)
        {{
            this.read = Marshal.GetFunctionPointerForDelegate(read);
        }}

        public void SetRelease(delegate3 release)
        {{
            this.release = Marshal.GetFunctionPointerForDelegate(release);
        }}

        // 调用函数指针
        public delegate2 GetRead()
        {{
            return Marshal.GetDelegateForFunctionPointer<delegate2>(read);
        }}

        public delegate3 GetRelease()
        {{
            return Marshal.GetDelegateForFunctionPointer<delegate3>(release);
        }}";
            var cgltf_file_options = @$"struct cgltf_file_options
{{";
            data.Replace(cgltf_file_options, cgltf_file_options + addTo_cgltf_file_options);

            return data;
        }

        private static StringBuilder PostProcessFunc(Dictionary<string, EnumDeclarationSyntax> enums, StringBuilder data, bool is_write = false)
        {
            /*
             * c中使用枚举值没有带枚举名，需要修正
             */
            foreach (var e in enums)
            {
                foreach (var eM in e.Value.Members)
                {
                    data = data.Replace($"{eM.Identifier.Text})", $"{e.Key}.{eM.Identifier.Text})");
                    data = data.Replace($"{eM.Identifier.Text}:", $"{e.Key}.{eM.Identifier.Text}:");
                    data = data.Replace($"{eM.Identifier.Text} ", $"{e.Key}.{eM.Identifier.Text} ");
                }
            }

            /*
             * c字符串和c#不同，所以字符串需要转换为sbyte[], 例如："abc" => const sbyte[] abc = new sbyte[] { 97, 98, 99 }
             * cgltf.h我直接把sbyte[]存储为全局static
             * cgltf_write.h中由于有结构引用，所以全局静态存储的是sbyte*, 需要特定函数首先申请内存，然后将字符串sbyte[]拷贝到sbyte*中
             */
            // 定义正则表达式匹配""
            string pattern = "\"(.*?)\"";
            if (is_write)
                pattern = "\\\"(.*?)(?<!\\\\)\\\"";
            // 创建一个列表存储替换的内容
            List<(string constName, string sourceStr)> replacements = new();
            // 执行替换，同时记录替换的内容
            string result = data.ToString();
            result = Regex.Replace(result, pattern, m =>
            {
                // 获取捕获的内容
                string content = m.Groups[1].Value;
                if (content.Contains("\\\""))//双引号之中的引号需要\"，从文本提取时会都提取出来
                {
                    content = content.Replace("\\\"", "\"");
                }
                if (content.Contains("\\n"))
                {
                    content = content.Replace("\\n", "\n");
                }
                // 如果已经替换过，直接返回替换后的内容，避免变量名重复
                foreach (var con in replacements)
                {
                    if (con.sourceStr == content)
                    {
                        return con.constName;
                    }
                }

                string pattern = "[^a-zA-Z_]"; // 匹配非英文字母和下划线的字符
                bool containsNonEnglish = Regex.IsMatch(content, pattern);
                if (containsNonEnglish) //特殊字符不能作为变量名
                {
                    var constName = $"const_{replacements.Count}";
                    // 将内容加入列表
                    replacements.Add((constName, content));
                    // 返回内容进行替换
                    return constName;
                }
                else
                {
                    var constName = $"const_{content}";
                    // 将内容加入列表
                    replacements.Add((constName, content));
                    // 返回内容进行替换
                    return constName;
                }
            });

            data = new StringBuilder();

            if (!is_write)
            {
                // 添加sbyte[]作为static
                foreach (var con in replacements)
                {
                    data.Append($"static sbyte[] {con.constName} = new sbyte[] {{ ");
                    var bytes = System.Text.Encoding.UTF8.GetBytes(con.sourceStr);
                    foreach (var c in bytes)
                    {
                        data.Append((int)c + ", ");
                    }
                    data.Append((int)'\0' + $"}};// \"{con.sourceStr}\"\n");//c语言中字符串以\0结尾
                }
            }
            else
            {
                // 添加sbyte*作为static
                foreach (var con in replacements)
                {
                    data.Append($"static sbyte* {con.constName};// \"{con.sourceStr.Replace("\n", "\\n")}\"\n");
                }
                // 添加函数，将sbyte[]拷贝到sbyte*
                data.Append("public static void InitConst()\n{\n");
                foreach (var con in replacements)
                {
                    data.Append($"sbyte[] _{con.constName} = new sbyte[] {{ ");
                    var bytes = System.Text.Encoding.UTF8.GetBytes(con.sourceStr);
                    foreach (var c in bytes)
                    {
                        data.Append((int)c + ", ");
                    }
                    data.Append((int)'\0' + $"}};// \"{con.sourceStr.Replace("\n", "\\n")}\"\n");//c语言中字符串以\0结尾
                    data.AppendLine($"{con.constName} = (sbyte*)Marshal.AllocHGlobal(_{con.constName}.Length);");
                    data.Append(@$"fixed (sbyte* src = _{con.constName})
{{
    Buffer.MemoryCopy(src, {con.constName}, _{con.constName}.Length, _{con.constName}.Length);
}}");
                    data.AppendLine();
                }
                data.Append("\n}");

                // 添加函数，释放sbyte*
                data.Append("public static void ReleaseConst()\n{\n");
                foreach (var con in replacements)
                {
                    data.Append($"Marshal.FreeHGlobal((IntPtr){con.constName});\n");
                }
                data.Append("\n}");
            }

            data.Append(result);

            /*
             * cgltf_memory_options和cgltf_file_options的函数指针处理，使用了chatgpt的建议
             */
            data.Replace("alloc_func ?", "alloc_func != IntPtr.Zero ?");
            data.Replace("alloc_func :", "GetAllocFunc() :");
            data.Replace("alloc_func(", "GetAllocFunc()(");
            data.Replace("free_func ?", "free_func != IntPtr.Zero ?");
            data.Replace("free_func :", "GetFreeFunc() :");
            data.Replace("free_func(", "GetFreeFunc()(");
            data.Replace("alloc_func) == (null)", "alloc_func) == (IntPtr.Zero)");
            data.Replace("free_func) == (null)", "free_func) == (IntPtr.Zero)");

            data.Replace("read ?", "read != IntPtr.Zero ?");
            data.Replace("read :", "GetRead() :");
            data.Replace("release ?", "release != IntPtr.Zero ?");
            data.Replace("release :", "GetRelease() :");

            /*
             * 函数指针传递在c#中使用的是将方法直接赋值给委托，所以不需要&符号
             */
            data.Replace("alloc_func = &cgltf_default_alloc", "SetAllocFunc(cgltf_default_alloc)");
            data.Replace("free_func = &cgltf_default_free", "SetFreeFunc(cgltf_default_free)");
            data.Replace(": &cgltf_default_alloc", ": cgltf_default_alloc");
            data.Replace(": &cgltf_default_free", ": cgltf_default_free");

            data.Replace(": &cgltf_default_file_read", ": cgltf_default_file_read");
            data.Replace(": &cgltf_default_file_release", ": cgltf_default_file_release");
            /*
             * 传入参数为sbyte*，但实际是字符串的，参数用sbyte[]代替
             */
            if (!is_write)
            {
                result = data.ToString();
                data = new StringBuilder();
                using (StringReader reader = new StringReader(result))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (!is_write)
                        {
                            if (line.Contains(" cgltf_json_") && line.Contains(" sbyte* "))
                                data.AppendLine(line.Replace(" sbyte* ", " sbyte[] "));
                            else
                                data.AppendLine(line);
                        }
                        else
                        {
                            /*if (line.Contains("cgltf_write_") && line.Contains(" sbyte* "))
                                if (line.Contains("label"))
                                    data.AppendLine(line.Replace(" sbyte* label", " sbyte[] label"));
                                else
                                    data.AppendLine(line.Replace(" sbyte* ", " sbyte[] "));
                            else*/
                            data.AppendLine(line);
                        }
                    }
                }
            }
            /*
             * float数
             */
            data.Replace(".f)", ".0f)");

            /*
             * 移除包含(void)行
             */
            result = data.ToString();
            data = new StringBuilder();
            using (StringReader reader = new StringReader(result))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.Contains("(void)"))
                        continue;
                    data.AppendLine(line);
                }
            }

            /*
             * 修改局部变量名token_count，因为它后面又定义了一个
             */

            var tokens = new List<(string variableDeclarations, string variableName)>()
            {
                ("int token_count", "token_count"),
                ("cgltf_result json_result", "json_result")
            };
            foreach (var v in tokens)
            {
                result = data.ToString();
                data = new StringBuilder();
                using (StringReader reader = new StringReader(result))
                {
                    int findedToken = 0;
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.Contains(v.variableDeclarations))
                        {
                            findedToken++;
                            if (findedToken == 1)
                                data.AppendLine(line.Replace(v.variableDeclarations, $"{v.variableDeclarations}1"));
                            else
                                data.AppendLine(line);
                        }
                        else
                        {
                            if (findedToken == 1)
                            {
                                if (line.Contains($"({v.variableName}"))
                                    data.AppendLine(line.Replace($"({v.variableName}", $"({v.variableName}1"));
                                else
                                    data.AppendLine(line);
                            }
                            else
                                data.AppendLine(line);
                        }
                    }
                }
            }

            /*
             * 添加修改过后的 cgltf_default_file_read方法
             */

            var cgltf_default_file_read = $@"
public static cgltf_result cgltf_default_file_read(cgltf_memory_options* memory_options, cgltf_file_options* file_options, sbyte* path, ulong* size, void** data)
{{
        delegate0 memory_alloc = memory_options->alloc_func != IntPtr.Zero ? memory_options->GetAllocFunc() : cgltf_default_alloc;
        delegate1 memory_free = memory_options->free_func != IntPtr.Zero ? memory_options->GetFreeFunc() : cgltf_default_free;

        // 使用 Encoding.UTF8 解码字节数组
        string pathStr = System.Text.Encoding.UTF8.GetString((byte*)path, (int)CRuntime.strlen(path));

        if (!System.IO.File.Exists(pathStr))
        {{
            return (cgltf_result)(cgltf_result.cgltf_result_file_not_found);
        }}

        ulong file_size = (ulong)((size) != null ? *size : 0);
        if ((file_size) == (0))
        {{
            long length = 0;
            var info = new System.IO.FileInfo(pathStr);
            length = info.Length;
            if ((length) < (0))
            {{
                return (cgltf_result)(cgltf_result.cgltf_result_io_error);
            }}

            file_size = ((ulong)(length));
        }}

        sbyte* file_data = (sbyte*)(memory_alloc(memory_options->user_data, (ulong)(file_size)));
        var span = new Span<byte>(file_data, (int)file_size);
        if (file_data == null)
        {{
            return (cgltf_result)(cgltf_result.cgltf_result_out_of_memory);
        }}

        var fs = new System.IO.FileStream(pathStr, System.IO.FileMode.Open, System.IO.FileAccess.Read);
        var read_size = fs.Read(span);
        fs.Close();

        if ((ulong)read_size != file_size)
        {{
            memory_free(memory_options->user_data, file_data);
            return (cgltf_result)(cgltf_result.cgltf_result_io_error);
        }}

        if ((size) != null)
        {{
            *size = (ulong)(file_size);
        }}

        if ((data) != null)
        {{
            *data = file_data;
        }}

        return (cgltf_result)(cgltf_result.cgltf_result_success);
}}";
            if (!is_write)
                data.Append(cgltf_default_file_read);

            /*
             * 某些不是ulong的和ulong数一起操作
             */
            data.Replace("(ulong)(tokens[i].end - start)", "(ulong)((ulong)tokens[i].end - start)");
            data.Replace("(ulong)(sizeof(jsmntok_t)", "(ulong)((ulong)sizeof(jsmntok_t)");

            /*
             * 某些int和uint的操作
             */
            data.Replace("buffer = (uint)((buffer << 6) | index);", "buffer = (uint)((buffer << 6) | (uint)index);");
            data.Replace("((byte)(buffer >> (buffer_bits - 8)));", "((byte)(buffer >> ((int)buffer_bits - 8)));");

            /*
             * 某些错误
             */
            data.Replace("p1 ?", "p1 != null ?");
            data.Replace("p2->parent ?", "p2->parent != null ?");
            data.Replace("(us) != 0 ?", "(us) != null ?");
            data.Replace("(s0) != 0 ?", "(s0) != null ?");
            data.Replace("(s0) != 0 ?", "(s0) != null ?");
            data.Replace("file_data : (0);", "file_data : (null);");
            data.Replace($@"default:
            ;", $@"default: break;
            ;");

            data.Replace($@"jsmn_parser parser = (jsmn_parser)(stackalloc jsmn_parser[]
    {{
        0,
        0,
        0
    }}; ) ; ", "jsmn_parser parser = new();");
            data.Replace("0 /", "SIZE_MAX /");
            if (is_write)
                data.Replace("params", "@params");
            if (is_write)
            {
                data.Replace("if ((has_extension) != 0)", "if ((has_extension) != false)");
                data.Replace("(bool)(0)", "(bool)(false)");
                data.Replace("(bool)(accessor->normalized)", "(bool)(accessor->normalized > 0 ? true : false)");
                data.Replace(" (val) != 0 ?", " (val) != true ?");
                data.Replace("(bool)(material->double_sided)", "(bool)(material->double_sided > 0 ? true : false)");
            }
            if (!is_write)
                data.AppendLine("const int SIZE_MAX = 65535;");

            if (is_write)
            {
                data.AppendLine(@$"public static int cgltf_check_floatarray(float* vals, int dim, float val)
{{
    while ((dim--) != 0)
    {{
        if (vals[dim] != val)
        {{
            return 1;
        }}
    }}
    return 0;
}}");
                data.AppendLine();

                data.Append($@"public static cgltf_result cgltf_write_file( cgltf_options* options, string path, cgltf_data* data)
    {{
        ulong expected = cgltf_write(options, null, 0, data);
        sbyte* buffer = (sbyte*)CRuntime.malloc(expected);
        ulong actual = cgltf_write(options, buffer, expected, data);
        if (expected != actual)
        {{
            System.Diagnostics.Trace.TraceError(""Error: expected %zu bytes but wrote %zu bytes.\n"", expected, actual);
        }}

        if (!System.IO.File.Exists(path))
        {{
            return cgltf_result.cgltf_result_file_not_found;
        }}
        var file = System.IO.File.Open(path, System.IO.FileMode.Open);

        // Note that cgltf_write() includes a null terminator, which we omit from the file content.
        if (options->type == cgltf_file_type.cgltf_file_type_glb)
        {{
            cgltf_write_glb(file, buffer, actual - 1, data->bin, data->bin_size);
        }}
        else
        {{
            // Write a plain JSON file.
            file.Write(new ReadOnlySpan<byte>(buffer, (int)(actual - 1)));
        }}
        file.Close();
        CRuntime.free(buffer);
        return cgltf_result.cgltf_result_success;
    }}");
                data.AppendLine();

                data.Append($@"static void cgltf_write_glb(System.IO.Stream file, void* json_buf, ulong json_size, void* bin_buf, ulong bin_size)
{{
    ulong GlbHeaderSize = 12;
    ulong GlbChunkHeaderSize = 8;
    byte[] header = new byte[GlbHeaderSize];
    byte[] chunk_header = new byte[GlbChunkHeaderSize];
    byte[] json_pad = new byte[] {{ 0x20, 0x20, 0x20 }};
    byte[] bin_pad = new byte[] {{ 0, 0, 0 }};

    ulong json_padsize = (json_size % 4 != 0) ? 4 - json_size % 4 : 0;
    ulong bin_padsize = (bin_size % 4 != 0) ? 4 - bin_size % 4 : 0;
    ulong total_size = GlbHeaderSize + GlbChunkHeaderSize + json_size + json_padsize;
    if (bin_buf != null && bin_size > 0)
    {{
        total_size += GlbChunkHeaderSize + bin_size + bin_padsize;
    }}

    // Write a GLB header
    fixed (byte* headerPtr = header)
    {{
        fixed (uint* p = &GlbMagic)
            CRuntime.memcpy(headerPtr, p, 4);
        fixed (uint* p = &GlbVersion)
            CRuntime.memcpy(headerPtr + 4, p, 4);
        CRuntime.memcpy(headerPtr + 8, &total_size, 4);
        file.Write(header, 0, (int)GlbHeaderSize);
    }}

    file.Seek(0, System.IO.SeekOrigin.End);// 将文件流的当前位置设置为文件的末尾

    // Write a JSON chunk (header & data)
    fixed (byte* chunk_headerPtr = chunk_header)
    {{
        ulong json_chunk_size = (ulong)(json_size + json_padsize);
        CRuntime.memcpy(chunk_headerPtr, &json_chunk_size, 4);
        fixed (uint* p = &GlbVersion)
            CRuntime.memcpy(chunk_headerPtr + 4, p, 4);
        file.Write(chunk_header, 0, (int)GlbChunkHeaderSize); file.Seek(0, System.IO.SeekOrigin.End);
        file.Write(new ReadOnlySpan<byte>(json_buf, (int)json_size)); file.Seek(0, System.IO.SeekOrigin.End);
        file.Write(json_pad, 0, (int)json_padsize); file.Seek(0, System.IO.SeekOrigin.End);

        if (bin_buf != null && bin_size > 0)
        {{
            // Write a binary chunk (header & data)
            ulong bin_chunk_size = (ulong)(bin_size + bin_padsize);
            CRuntime.memcpy(chunk_headerPtr, &bin_chunk_size, 4);
            fixed (uint* p = &GlbMagicBinChunk)
                CRuntime.memcpy(chunk_headerPtr + 4, p, 4);
            file.Write(chunk_header, 0, (int)GlbChunkHeaderSize); file.Seek(0, System.IO.SeekOrigin.End);
        }}
    }}


    file.Write(new ReadOnlySpan<byte>(bin_buf, (int)bin_size)); file.Seek(0, System.IO.SeekOrigin.End);
    file.Write(bin_pad, 0, (int)bin_padsize); file.Seek(0, System.IO.SeekOrigin.End);
}}");
                data.AppendLine();
            }

            if (is_write)
            {
                data.Replace("(ulong)(-1)", "unchecked((ulong)(-1))");
            }
            return data;
        }

        private static void Process()
        {
            // 查找包含标准c库的头文件的include文件夹
            string findIncludeFolder(string rootFolder)
            {
                foreach (var folder in Directory.EnumerateDirectories(rootFolder))
                {
                    if (folder.Contains("include"))
                    {
                        return folder;
                    }
                    else
                    {
                        var f = findIncludeFolder(folder);
                        if (f == string.Empty)
                            continue;
                        else
                            return f;
                    }
                }

                return string.Empty;
            }

            var includeFolder = new List<string>();// 添加CppSharp的nuget包时会包含clang头文件，include引用时需要。
            var downloadFromGithubInclude = @"src-include";
            if (Path.Exists(downloadFromGithubInclude))
                includeFolder.Add(downloadFromGithubInclude);
            var cppSharpInclude = Path.GetFullPath(findIncludeFolder(System.Environment.CurrentDirectory));
            includeFolder.Add(cppSharpInclude);

            //var file = "test.h";
            var readFile = "cgltf.h";
            var readFileName = Path.GetFileNameWithoutExtension(readFile);
            var writeFile = "cgltf_write.h";
            var writeFileName = Path.GetFileNameWithoutExtension(writeFile);

            string cgltfVersion = string.Empty;
            foreach (var line in File.ReadLines(readFile))
            {
                if (line.Contains("* Version:"))
                {
                    cgltfVersion = line.Split(":")[1].Trim();
                    break;
                }
            }

            // 获取所有的可以使用CRuntime类转换的c函数名
            MethodInfo[] methods = typeof(Hebron.Runtime.CRuntime).GetMethods(BindingFlags.Public | BindingFlags.Static);
            foreach (MethodInfo method in methods)
            {
                Hebron.Utility.NativeFunctions.Add(method.Name);
            }

            if (File.Exists(readFile))
            {
                Logger.Info($"Processing {readFile}");
                var parseParameters = new RoslynConversionParameters
                {
                    InputPath = readFile,
                    Args = new[]
                    {
                        "-v", // 启用详细日志
                        "-nostdinc", // 禁用系统路径, 即不包含标准头文件, 避免安装与不安装VS的C++组件时分析不一致
                        "-std=c99", // 使用 C99 标准，好像没作用
                        "-I", cppSharpInclude, // 指定包含CppSharp里自带的clang头文件
                        "-I", downloadFromGithubInclude, //
                    },
                    Defines = new[]
                    {
                        "DEFAULT",
                        "CGLTF_IMPLEMENTATION",
                    },
                    SkipFunctions = new[]
                    {
                        "DEFAULT",
                        "cgltf_default_file_read" // c语言中使用fopen读取文件，c#中使用c#的类去读取
                    },

                    AdditionalIncludeDirectories = includeFolder.ToArray()
                };

                var parseResult = RoslynCodeConverter.Convert(parseParameters);

                // Post processing
                Logger.Info("Post processing...");

                var outputCommon = new StringBuilder();
                Write(parseResult.NamedEnums, outputCommon);
                Write(parseResult.UnnamedEnumValues, outputCommon);
                Write(parseResult.GlobalVariables, outputCommon);
                Write(parseResult.Delegates, outputCommon);
                Write(parseResult.Structs, outputCommon);
                var outputCommonCode = PostProcess(outputCommon);

                var outputFunc = new StringBuilder();
                Write(parseResult.Functions, outputFunc);
                var outputFuncCode = PostProcessFunc(parseResult.NamedEnums, outputFunc);

                writeToFile(readFileName, "Common", outputCommonCode.ToString());
                writeToFile(readFileName, "Func", outputFuncCode.ToString());
            }

            // cgltf_write.h的结构等写入cgltf.Generated.Common
            // 函数写入cgltf_write.Generated.Func
            if (File.Exists(writeFile))
            {
                Logger.Info($"Processing {writeFile}");
                var parseParameters = new RoslynConversionParameters
                {
                    InputPath = writeFile,
                    Args = new[]
                    {
                        "-v", // 启用详细日志
                        //"-nostdinc", // 禁用系统路径, 即不包含标准头文件, 避免安装与不安装VS的C++组件时分析不一致
                        "-std=c99", // 使用 C99 标准，好像没作用
                        "-I", cppSharpInclude, // 指定包含CppSharp里自带的clang头文件
                        "-I", downloadFromGithubInclude, //
                        "-I", Path.GetFullPath(System.Environment.CurrentDirectory) //依赖cgltf.h/
                    },
                    Defines = new[]
                    {
                        "DEFAULT",
                        "CGLTF_IMPLEMENTATION",
                        "CGLTF_WRITE_IMPLEMENTATION"
                    },
                    SkipFunctions = new[]
                    {
                        "DEFAULT",
                        "cgltf_default_file_read", // c语言中使用fopen读取文件，c#中使用c#的类去读取
                        "cgltf_write_glb", //使用fwrite
                        "cgltf_write_file",
                        "cgltf_check_floatarray" //处理#define的true错误
                    },

                    AdditionalIncludeDirectories = includeFolder.ToArray()
                };

                var parseResult = RoslynCodeConverter.Convert(parseParameters);

                // Post processing
                Logger.Info("Post processing...");

                var outputCommon = new StringBuilder();
                Write(parseResult.NamedEnums, outputCommon);
                Write(parseResult.UnnamedEnumValues, outputCommon);
                Write(parseResult.GlobalVariables, outputCommon);
                Write(parseResult.Delegates, outputCommon);
                Write(parseResult.Structs, outputCommon);
                var outputCommonCode = PostProcess(outputCommon, true);

                var outputFunc = new StringBuilder();
                Write(GetAllWriteFunc(parseResult.Functions), outputFunc);
                var outputFuncCode = PostProcessFunc(parseResult.NamedEnums, outputFunc, true);

                writeToFile(readFileName, "Common", outputCommonCode.ToString(), true);
                writeToFile("cgltfwrite", "Func", outputFuncCode.ToString(), true);//cgltf_write.h里有cgltf_write函数
            }

            void writeToFile(string fileName, string fileTag, string data, bool is_write = false)
            {
                var sb = new StringBuilder();
                sb.AppendLine(string.Format("// Auto generated by yangzhou"));
                sb.AppendLine(string.Format("// cgltf version: {0}", cgltfVersion));
                sb.AppendLine();

                sb.AppendLine("using System;");
                sb.AppendLine("using System.Runtime.InteropServices;");
                sb.AppendLine("using Hebron.Runtime;");
                if (is_write && fileTag == "Func")
                    sb.AppendLine("using static cgltf.NET.cgltf;");
                sb.AppendLine();

                sb.Append("namespace cgltf.NET;\n\t");
                sb.AppendLine($"public static unsafe partial class {fileName}\n\t{{");

                data = sb.ToString() + data;
                data += "}";

                string currentDirectoryPath = System.Environment.CurrentDirectory;
                if (currentDirectoryPath.Contains("cgltf.NET.Generator"))
                {
                    string solutionDirectory = currentDirectoryPath.Split("cgltf.NET.Generator")[0];
                    string cgltfNETProjectDirectory = Path.Combine(solutionDirectory, "cgltf.NET");
                    File.WriteAllText(Path.Combine(cgltfNETProjectDirectory, $"{fileName}.Generated." + fileTag + ".cs"), data);
                }
            }

            Dictionary<string, MethodDeclarationSyntax> GetAllWriteFunc(Dictionary<string, MethodDeclarationSyntax> func)
            {
                var writeFunDic = new Dictionary<string, MethodDeclarationSyntax>();
                var splitFun = "jsmn_parse_string";//这之后的
                bool isWriteFun = false;
                foreach (var f in func)
                {
                    if (isWriteFun)
                        writeFunDic.Add(f.Key, f.Value);
                    else
                    {
                        if (f.Key == splitFun)
                            isWriteFun = true;
                        continue;
                    }
                }
                return writeFunDic;
            }
        }

        private static void Main(string[] args)
        {
            Process();
            Console.WriteLine("Hello, World!");
        }
    }
}