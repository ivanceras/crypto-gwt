package com.googlecode.cryptogwttests;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import net.sf.cglib.proxy.Enhancer;
import net.sf.cglib.proxy.MethodInterceptor;
import net.sf.cglib.proxy.MethodProxy;

public class Adaptor {
    private static final String EMULATED_PREFIX = "";
    
    private static Map<Class<?>, Mapper<?>> specialCases = new HashMap<Class<?>, Mapper<?>>();

    static {
        specialCases.put(javax.crypto.spec.SecretKeySpec.class,
                new Mapper<javax.crypto.spec.SecretKeySpec>() {
                    public javax.crypto.spec.SecretKeySpec map(Object object) {
                        javax.crypto.spec.SecretKeySpec spec = 
                            (javax.crypto.spec.SecretKeySpec) object;
                        return new SecretKeySpec(spec.getEncoded(), spec.getAlgorithm());
                    }
            
                });
        
        specialCases.put(javax.crypto.spec.IvParameterSpec.class,
                new Mapper<javax.crypto.spec.IvParameterSpec>() {
                    public javax.crypto.spec.IvParameterSpec map(Object object) {
                        javax.crypto.spec.IvParameterSpec spec = 
                            (javax.crypto.spec.IvParameterSpec) object;
                        return new javax.crypto.spec.IvParameterSpec(spec.getIV());
                    }           
                });
        
        specialCases.put(javax.crypto.spec.PBEKeySpec.class,
                new Mapper<javax.crypto.spec.PBEKeySpec>() {
                    public javax.crypto.spec.PBEKeySpec map(Object object) {
                        javax.crypto.spec.PBEKeySpec spec =
                            (javax.crypto.spec.PBEKeySpec) object;
                        return new javax.crypto.spec.PBEKeySpec(
                                spec.getPassword(),
                                spec.getSalt(),
                                spec.getIterationCount(),
                                spec.getKeyLength());
                    }
                });        
        
//        specialCases.put(javax.crypto.SecretKey.class,
//                new Mapper<javax.crypto.SecretKey>() {
//                    public javax.crypto.SecretKey map(Object object) {
//                        javax.crypto.SecretKey secretKey =
//                            (javax.crypto.SecretKey) object;
//                        return new javax.crypto.spec.SecretKeySpec(
//                                secretKey.getEncoded(), secretKey.getAlgorithm());
//                    }
//                });
        
//        specialCases.put(javax.crypto.interfaces.PBEKey.class,
//                new Mapper<javax.crypto.interfaces.PBEKey>() {
//                    public javax.crypto.interfaces.PBEKey map(Object object) {
//                        final javax.crypto.interfaces.PBEKey secretKey =
//                            (javax.crypto.interfaces.PBEKey) object;
//                        return new javax.crypto.interfaces.PBEKey() {
//
//                            private static final long serialVersionUID = 4222351196900671407L;
//
//                            public int getIterationCount() {
//                                return secretKey.getIterationCount();
//                            }
//
//                            public char[] getPassword() {
//                                return secretKey.getPassword();
//                            }
//
//                            public byte[] getSalt() {
//                                return secretKey.getSalt();
//                            }
//
//                            public String getAlgorithm() {
//                                return secretKey.getAlgorithm();
//                            }
//
//                            public byte[] getEncoded() {
//                                return secretKey.getEncoded();
//                            }
//
//                            public String getFormat() {
//                                return secretKey.getFormat();
//                            }
//                        };
//                    }
//                });
        
//        specialCases.put(javax.crypto.interfaces.PBEKey.class,
//                new Mapper<javax.crypto.interfaces.PBEKey>() {
//                    public javax.crypto.interfaces.PBEKey map(Object object) {
//                        final javax.crypto.interfaces.PBEKey secretKey =
//                            (javax.crypto.interfaces.PBEKey) object;
//                        return new javax.crypto.interfaces.PBEKey() {
//
//                            private static final long serialVersionUID = 4222351196900671407L;
//
//                            public int getIterationCount() {
//                                return secretKey.getIterationCount();
//                            }
//
//                            public char[] getPassword() {
//                                return secretKey.getPassword();
//                            }
//
//                            public byte[] getSalt() {
//                                return secretKey.getSalt();
//                            }
//
//                            public String getAlgorithm() {
//                                return secretKey.getAlgorithm();
//                            }
//
//                            public byte[] getEncoded() {
//                                return secretKey.getEncoded();
//                            }
//
//                            public String getFormat() {
//                                return secretKey.getFormat();
//                            }
//                        };
//                    }
//                });
    }
    
    @SuppressWarnings("unchecked")
    public static <T> T adapt(final Object o, Class<? extends T> type) {
               
        // Handle null
        if (o == null) return type.cast(null);
        
        // Handle subclasses
        if (type.isInstance(o)) return type.cast(o);
        
        // Handle primitive types
        if (type.isPrimitive() || o.getClass().isPrimitive()) {
            // Rely on autoboxing
            return (T) o;
        }
        
        // Handle other special cases
        Mapper<T> mapper = (Mapper<T>) specialCases.get(type);
        if (mapper != null) {
            return mapper.map(o);
        }
        
        // Handle everything else
        Class<?>[] interfaces = type.getInterfaces();
        Enhancer enhancer = new Enhancer();
        if (!type.isInterface()) {
            enhancer.setInterfaces(interfaces);
        } 
        enhancer.setSuperclass(type);
        enhancer.setCallback(new MethodInterceptor() {
            
            public Object intercept(Object paramObject, Method method,
                    Object[] args, MethodProxy paramMethodProxy)
                    throws Throwable {
                try {
                Class<?>[] adaptedTypes = adaptTypes(method.getParameterTypes());
                Object[] adaptedArgs = adaptArgs(args, method.getParameterTypes(), adaptedTypes);
                Method wrapped = getDeclaredMethodForHierarchy(o, method, adaptedTypes);                
                wrapped.setAccessible(true);
                Object result = wrapped.invoke(o, adaptedArgs);
                return adaptReturnValue(result, method.getReturnType());
                } catch(InvocationTargetException e) {
                    Throwable cause = e.getCause();
                    if (isEmulated(cause.getClass())) {
                        throw (Throwable) adapt(cause, unemulated(cause.getClass()));
                    }
                    if (isTargetForEmulation(cause.getClass())) {
                        throw (Throwable) adapt(cause, emulated(cause.getClass()));
                    }
                    throw cause;
                    
                }
            }

            private Object adaptReturnValue(Object result, Class<?> returnType) {
                if (result == null) return null;
                if (returnType.isAssignableFrom(result.getClass())) {
                    return returnType.cast(result);
                }                
                return adapt(result, returnType);
            }

            private Method getDeclaredMethodForHierarchy(final Object o,
                    Method method, Class<?>[] adaptedTypes)
                    throws NoSuchMethodException {
                Class<?> type = o.getClass();
                while (type != Object.class) {
                    try {
                    return type.getDeclaredMethod(method.getName(), adaptedTypes);
                    } catch (NoSuchMethodException e) {
                        // Squash
                    }
                    type = type.getSuperclass();
                }
                throw new NoSuchMethodException(o.getClass().getName() + "." + method.getName() +
                        "(" + Arrays.toString(adaptedTypes) + ")");
            }

            private Class<?>[] adaptTypes(Class<?>[] types) throws ClassNotFoundException {
                Class<?>[] result = new Class<?>[types.length];
                for (int i=0; i < types.length; i++) {                    
                    Class<?> type = types[i];
                    result[i] = adaptType(type);                   
                }
                return result;
            }
            
            private Class<?> adaptType(Class<?> type) throws ClassNotFoundException {
                if (isEmulated(type)) {
                    return unemulated(type);
                } else if(isTargetForEmulation(type)) {
                    return emulated(type);
                } else {
                    return type;
                }
            }

            private Class<?> narrowestOf(Class<?> a,
                    Class<?> b) {
                if (a.isAssignableFrom(b)) return b;
                return a;
            }

            private Object[] adaptArgs(Object[] args, Class<?>[] inTypes, Class<?>[] outTypes) throws ClassNotFoundException {
                Object[] result = new Object[args.length];
                for (int i=0; i<args.length; i++) {
                    final Object arg = args[i];
                    if (!outTypes[i].isAssignableFrom(inTypes[i])) result[i] = adapt(arg, 
                            narrowestOf(adaptType(arg != null ? arg.getClass() : Object.class), outTypes[i]));
                    else result[i] = arg;
                }
                return result;
            }


            private boolean isTargetForEmulation(Class<? extends Object> type) {                
                return classIsTargetForEmulation(type) || 
                    interfaceIsTargetForEmulation(type);
            }
            
            private boolean classIsTargetForEmulation(Class<? extends Object> type) {
                return type.getName().startsWith("java.security") ||
                    type.getName().startsWith("javax.crypto");
            }

            private boolean interfaceIsTargetForEmulation(
                    Class<? extends Object> type) {
                for (Class<?> iface : type.getInterfaces()) {
                    if (classIsTargetForEmulation(iface)) {
                        return true;
                    }
                }
                return false;
            }

            private Class<?> unemulated(Class<? extends Object> type) throws ClassNotFoundException {
                return Class.forName(type.getName().substring(EMULATED_PREFIX.length()));
            }
            
            private Class<?> emulated(Class<? extends Object> type) throws ClassNotFoundException {
                return Class.forName(EMULATED_PREFIX + type.getName());
            }
        });
        try {
        return (T) enhancer.create();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Failed to create " + type + " from " + o.getClass(), e);
        }
    }

    private static boolean isEmulated(Class<?> type) {
        return type.getName().startsWith(EMULATED_PREFIX);
    }

}
