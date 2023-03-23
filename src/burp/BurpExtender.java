package burp;

import java.util.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.awt.Toolkit;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import static java.util.stream.Collectors.*;

import javax.swing.JMenuItem;

import mjson.Json;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ClipboardOwner
{
	private IExtensionHelpers helpers;

	private final static String NAME = "Copy as requests";
	private final static String SESSION_MENU_ITEM = NAME + " with session object";
	private final static String[] PYTHON_ESCAPE = new String[256];
	private final static String SESSION_VAR = "session";
	// private final static String TAB = "\t";
	private final static String TAB = "    ";

	static {
		for (int i = 0x00; i <= 0xFF; i++) PYTHON_ESCAPE[i] = String.format("\\x%02x", i);
		for (int i = 0x20; i < 0x80; i++) PYTHON_ESCAPE[i] = String.valueOf((char)i);
		PYTHON_ESCAPE['\n'] = "\\n";
		PYTHON_ESCAPE['\r'] = "\\r";
		PYTHON_ESCAPE['\t'] = "\\t";
		PYTHON_ESCAPE['"'] = "\\\"";
		PYTHON_ESCAPE['\\'] = "\\\\";
	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName(NAME);
		callbacks.registerContextMenuFactory(this);
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
		if (messages == null || messages.length == 0) return null;
		JMenuItem i1 = new JMenuItem(NAME);
		i1.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				copyMessages(messages, false);
			}
		});
		JMenuItem i2 = new JMenuItem(SESSION_MENU_ITEM);
		i2.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				copyMessages(messages, true);
			}
		});
		return Arrays.asList(i1, i2);
	}

	private enum BodyType {JSON, DATA};

	private void copyMessages(IHttpRequestResponse[] messages, boolean withSessionObject) {
		StringBuilder py = new StringBuilder("import requests");
		String requestsMethodPrefix =
			"\n" + (withSessionObject ? SESSION_VAR : "requests") + ".";
		int i = 0;

		if (withSessionObject) {
			py.append("\n\n" + SESSION_VAR + " = requests.session()");
		}

		for (IHttpRequestResponse message : messages) {
			IRequestInfo ri = helpers.analyzeRequest(message);
			byte[] req = message.getRequest();
			String prefix = "";
			if (messages.length > 1) {
				prefix = "burp" + i++ + "_";
			}
			py.append("\n\n").append(prefix).append("url = \"");
			py.append(escapeQuotes(ri.getUrl().toString().split("\\?")[0]));
			py.append('"');

			boolean hasParams = processUrlParams(prefix, py, ri.getUrl());

			List<String> headers = ri.getHeaders();
			boolean cookiesExist = processCookies(prefix, py, headers);
			py.append('\n').append(prefix).append("headers = {\n\t");
			processHeaders(py, headers);
			py.append("\n}");
			BodyType bodyType = processBody(prefix, py, req, ri);
			py.append(requestsMethodPrefix);
			py.append(ri.getMethod().toLowerCase());
			py.append('(').append(prefix).append("url");
			if (hasParams) py.append(", params=").append(prefix).append("params");
			py.append(", headers=").append(prefix).append("headers");
			if (cookiesExist) py.append(", cookies=").append(prefix).append("cookies");
			if (bodyType != null) {
				String kind = bodyType.toString().toLowerCase();
				py.append(", ").append(kind).append('=').append(prefix).append(kind);
			}
			py.append(')');
		}

		Toolkit.getDefaultToolkit().getSystemClipboard()
			.setContents(new StringSelection(py.toString()), this);
	}

	private boolean processUrlParams(String prefix, StringBuilder py,
			URL url) {
		String urlQuery = url.getQuery();
		if (urlQuery != null && urlQuery.length() > 0) {
			py.append('\n').append(prefix).append("params = {");
			Map<String, List<String>> urlParams = splitQuery(url.getQuery());
			
			for (Map.Entry<String, List<String>> entry : urlParams.entrySet()) {
				py.append("\n\t");
				escapeString(entry.getKey(), py);
				py.append(": ");
				List<String> value = entry.getValue();
				if (value.size() == 1) {
					String vvalue = value.get(0);
					if (vvalue == null) {
						py.append("\"\"");
					} else {
						escapeString(vvalue, py);
					}
				} else {
					py.append("[");
					for (String v : value) {
						py.append("\n\t\t");
						if (v == null) {
							py.append("\"\"");
						} else {
							escapeString(v, py);
						}
						py.append(",");
					}
					py.append("\n\t]");
				}
				py.append(",");
			}
			py.append("\n}");
			return true;
		}
		return false;		
	}

	private static boolean processCookies(String prefix, StringBuilder py,
			List<String> headers) {
		ListIterator<String> iter = headers.listIterator();
		boolean cookiesExist = false;
		while (iter.hasNext()) {
			String header = iter.next();
			if (!header.toLowerCase().startsWith("cookie:")) continue;
			iter.remove();
			for (String cookie : header.substring(8).split("; ?")) {
				if (cookiesExist) {
					py.append(",\n\t\"");
				} else {
					cookiesExist = true;
					py.append('\n').append(prefix).append("cookies = {\n\t\"");
				}
				String[] parts = cookie.split("=", 2);
				py.append(escapeQuotes(parts[0]));
				py.append("\": \"");
				py.append(escapeQuotes(parts[1]));
				py.append('"');
			}
		}
		if (cookiesExist) py.append("\n}");
		return cookiesExist;
	}

	private static final Collection<String> IGNORE_HEADERS = Arrays.asList("host:", "content-length:");

	private static void processHeaders(StringBuilder py, List<String> headers) {
		boolean firstHeader = true;
header_loop:
		for (String header : headers) {
			String lowerCaseHeader = header.toLowerCase();
			for (String headerToIgnore : IGNORE_HEADERS) {
				if (lowerCaseHeader.startsWith(headerToIgnore)) continue header_loop;
			}
			header = escapeQuotes(header);
			int colonPos = header.indexOf(':');
			if (colonPos == -1) continue;
			if (firstHeader) {
				firstHeader = false;
				py.append('"');
			} else {
				py.append(",\n\t\"");
			}
			py.append(header, 0, colonPos);
			py.append("\": \"");
			py.append(header, colonPos + 2, header.length());
			py.append('"');
		}
	}

	private BodyType processBody(String prefix, StringBuilder py,
			byte[] req, IRequestInfo ri) {
		int bo = ri.getBodyOffset();
		if (bo >= req.length - 2) return null;
		py.append('\n').append(prefix);
		byte contentType = ri.getContentType();
		if (contentType == IRequestInfo.CONTENT_TYPE_JSON) {
			try {
				Json root = Json.read(byteSliceToString(req, bo, req.length));
				py.append("json = ");
				escapeJson(root, py, 1);
				return BodyType.JSON;
			} catch (Exception e) {
				// not valid JSON, treat it like any other kind of data
			}
		}
		py.append("data = ");
		if (contentType == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
			py.append('{');
			boolean firstKey = true;
			int keyStart = bo, keyEnd = -1;
			for (int pos = bo; pos < req.length; pos++) {
				byte b = req[pos];
				if (keyEnd == -1) {
					if (b == (byte)'=') {
						if (pos == req.length - 1) {
							if (!firstKey) py.append(",\n\t");
							escapeUrlEncodedBytes(req, py, keyStart, pos);
							py.append(": ''");
						} else {
							keyEnd = pos;
						}
					}
				} else if (b == (byte)'&' || pos == req.length - 1) {
					if (firstKey) firstKey = false; else py.append(",\n\t");
					escapeUrlEncodedBytes(req, py, keyStart, keyEnd);
					py.append(": ");
					escapeUrlEncodedBytes(req, py, keyEnd + 1,
							pos == req.length - 1 ? req.length : pos);
					keyEnd = -1;
					keyStart = pos + 1;
				}
			}
			py.append('}');
		} else {
			escapeBytes(req, py, bo, req.length);
		}
		return BodyType.DATA;
	}

	private static String escapeQuotes(String value) {
		return value.replace("\\", "\\\\").replace("\"", "\\\"")
			.replace("\n", "\\n").replace("\r", "\\r");
	}

	private void escapeUrlEncodedBytes(byte[] input, StringBuilder output,
			int start, int end) {
		if (end > start) {
			byte[] dec = helpers.urlDecode(Arrays.copyOfRange(input, start, end));
			escapeBytes(dec, output, 0, dec.length);
		} else {
			output.append("''");
		}
	}

	private static final String PYTHON_TRUE = "True", PYTHON_FALSE = "False", PYTHON_NULL = "None";

	private static String repeat(int count, String with) {
		String result = "";
		
		for (int i = 0; i < count; i++) {
			result += with;
		}
		return result;
	}

	private static void escapeJson(Json node, StringBuilder output, Integer depth) {
		if (node.isObject()) {
			output.append("{\n" + repeat(depth, TAB));
			Map<String, Json> tm = new TreeMap(String.CASE_INSENSITIVE_ORDER);
			tm.putAll(node.asJsonMap());
			final Iterator<Map.Entry<String, Json>> iter = tm.entrySet().iterator();
			if (iter.hasNext()) {
				appendIteratedEntry(iter, output, depth);
				while (iter.hasNext()) {
					output.append(",\n" + repeat(depth, TAB));
					appendIteratedEntry(iter, output, depth);
				}
			}
			output.append("\n" + repeat(depth-1, TAB) + "}");
		} else if (node.isArray()) {
			output.append("[\n" + repeat(depth, TAB));
			final Iterator<Json> iter = node.asJsonList().iterator();
			if (iter.hasNext()) {
				escapeJson(iter.next(), output, depth+1);
				while (iter.hasNext()) {
					output.append(",\n" + repeat(depth, TAB));
					escapeJson(iter.next(), output, depth+1);
				}
			}
			output.append("\n" + repeat(depth-1, TAB) + "]");
		} else if (node.isString()) {
			escapeString(node.asString(), output);
		} else if (node.isBoolean()) {
			output.append(node.asBoolean() ? PYTHON_TRUE : PYTHON_FALSE);
		} else if (node.isNull()) {
			output.append(PYTHON_NULL);
		} else if (node.isNumber()) {
			output.append(node.asString());
		}
	}

	private static void appendIteratedEntry(Iterator<Map.Entry<String, Json>> iter, StringBuilder output, Integer depth) {
		final Map.Entry<String, Json> e = iter.next();
		escapeString(e.getKey(), output);
		output.append(": ");
		escapeJson(e.getValue(), output, depth+1);
	}

	private static String byteSliceToString(byte[] input, int from, int till) {
		try {
			return new String(input, from, till - from, "ISO-8859-1");
		} catch (UnsupportedEncodingException uee) {
			throw new RuntimeException("All JVMs must support ISO-8859-1");
		}
	}

	private static void escapeString(String input, StringBuilder output) {
		output.append('"');
		int length = input.length();
		for (int pos = 0; pos < length; pos++) {
			output.append(PYTHON_ESCAPE[input.charAt(pos) & 0xFF]);
		}
		output.append('"');
	}

	private static void escapeBytes(byte[] input, StringBuilder output,
			int start, int end) {
		output.append('"');
		for (int pos = start; pos < end; pos++) {
			output.append(PYTHON_ESCAPE[input[pos] & 0xFF]);
		}
		output.append('"');
	}

	private static Map<String, List<String>> splitQuery(String query) {
        if (query == null || query.isEmpty()) {
            return Collections.emptyMap();
        }

        return Arrays.stream(query.split("&"))
                    .map(p -> splitQueryParameter(p))
                    .collect(groupingBy(e -> e.get0(), // group by parameter name
                            mapping(e -> e.get1(), toList())));// keep parameter values and assemble into list
    }

    private static Pair<String, String> splitQueryParameter(String parameter) {
        final String enc = "UTF-8";
        List<String> keyValue = Arrays.stream(parameter.split("="))
                .map(e -> {
                    try {
                        return URLDecoder.decode(e, enc);
                    } catch (UnsupportedEncodingException ex) {
                        throw new RuntimeUnsupportedEncodingException(ex);
                    }
                }).collect(toList());

        if (keyValue.size() == 2) {
            return new Pair(keyValue.get(0), keyValue.get(1));
        } else {
            return new Pair(keyValue.get(0), null);
        }
    }

    /** Runtime exception (instead of checked exception) to denote unsupported enconding */
    public static class RuntimeUnsupportedEncodingException extends RuntimeException {
        public RuntimeUnsupportedEncodingException(Throwable cause) {
            super(cause);
        }
    }

    /**
     * A simple pair of two elements
     * @param <U> first element
     * @param <V> second element
     */
    public static class Pair<U, V> {
        U a;
        V b;

        public Pair(U u, V v) {
            this.a = u;
            this.b = v;
        }

        public U get0() {
            return a;
        }

        public V get1() {
            return b;
        }
    }

	@Override
	public void lostOwnership(Clipboard aClipboard, Transferable aContents) {}
}
